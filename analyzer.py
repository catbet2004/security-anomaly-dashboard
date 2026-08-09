import numpy as np
import pandas as pd

from net_logs import collect_net_logs

REQUIRED_COLUMNS={
    "timestamp","username","ip_address","status"
}
#loads records from CSV file
def load_logs(file_path:str)->pd.DataFrame:
    try:
        logs=pd.read_csv(file_path)
    except FileNotFoundError as error:
        raise ValueError(
            f"File not found: {file_path}"
        ) from error
    except pd.error.EmptyDataError as error:
            raise ValueError("The CSV file is empty.") from error
    except pd.error.ParserError as error:
         raise ValueError("The file could not be read.") from error
    return logs

#check data has all required cols
def validate_cols(logs:pd.DataFrame)->None:
     missing_cols=REQUIRED_COLUMNS - set(logs.columns)

     if missing_cols:
          missing=", ".join(sorted(missing_cols))

          raise ValueError(f"These columns are missing in your CSV file: {missing} ")   

#cleans records before analyzing
def clean_logs(logs:pd.DataFrame)-> pd.DataFrame:
     clean=logs.copy()

     clean.columns=(clean.columns.str.strip().str.lower())

     validate_cols(clean)

     clean["username"]=(clean["username"].astype(str).str.strip().str.lower())
     clean["ip_address"]=(clean["ip_address"].astype(str).str.strip())
     clean["status"]=(clean["status"].astype(str).str.strip().str.lower())
     clean["timestamp"]=(clean["timestamp"].astype("string").str.strip())
     clean["timestamp"]=pd.to_datetime(clean["timestamp"], errors="coerce") #invalid changed to NaT

     clean=clean.replace("",pd.NA) #empty strings into missing vals

     clean=clean.dropna(subset=[
          "timestamp", "username", "ip_address", "status"
     ])

     clean=clean[clean["status"].isin(["success", "failed"])]

     clean=clean.reset_index(drop=True)

     return clean

#summarize IP login activity 
def ip_activity(logs:pd.DataFrame)->pd.DataFrame:

     analysis=logs.copy()

     analysis["failed"]=(
          analysis["status"]=="failed"
     ).astype(int)

     #mark login attempts during sus times
     analysis["date"]=analysis["timestamp"].dt.date
     analysis["hour"]=analysis["timestamp"].dt.hour
     analysis["off_hours"]=((analysis["hour"]<6)|(analysis["hour"]>=22).astype(int))

     ip_sum= (
          analysis.groupby(["ip_address","date"],as_index=False).agg(
               total_attempts=("status", "size"),
               failed_attempts=("failed", "sum"),
               unique_users=("username","nunique"),
               off_time_attempts=("off_hours", "sum"),
          )
     )
     ip_sum["failure_rate"]=(
          ip_sum["failed_attempts"]/ip_sum["total_attempts"]*100
     ).round(1)
     
     return ip_sum

def anom_score(ip_sum: pd.DataFrame)-> pd.DataFrame:
     score=ip_sum.copy()
     if score.empty:
          score["anomaly_score"]=pd.Series(dtype=float)
          score["suspicious"]=pd.Series(dtype=bool)
          score["risk_level"]=pd.Series(dtype="string")
          return score

     failures=score["failed_attempts"].to_numpy(dtype=float)

     avg_failures=np.mean(failures)
     failure_std=np.std(failures)

     if failure_std == 0:
          score["anomaly_score"]=0.0
     else:
          score["anomaly_score"]=(
               score["failed_attempts"]-avg_failures
          ) / failure_std

          score["suspicious"]=(
               score["anomaly_score"]>=1.5
          )
          assign_risk=[
               score["anomaly_score"]>=2.0,
               score["anomaly_score"]>=1.5,
          ]
          risky_lvls=["High","Medium"]

          score["risk_level"]=np.select(
               assign_risk,
               risky_lvls,
               default="Low",
          )

          score=score.sort_values(
               by="anomaly_score",
               ascending=False,

          ).reset_index(drop=True)

          return score


def main()-> None:

     logs=collect_net_logs()
     if logs.empty:
          print("\nNo supported authentication events were collected.")
          return
     try:
          cleaned_logs=clean_logs(logs)
          ip_sum=ip_activity(cleaned_logs)
          score_ips=anom_score(ip_sum)
     except ValueError as error:
         print(f"Error: {error}")
         return

     print ("Original data:")
     print(logs)

     print("\nNumber of valid records:")
     print(len(cleaned_logs))

     print("\nCleaned data:")
     print(cleaned_logs)

     print("\nColumn data types:")
     for column, data_type in cleaned_logs.dtypes.items():
         print (f"{column}: {data_type}")

     print("\nIP address summary:")
     print(ip_sum)

     print("\nAnomaly results:")
     print(score_ips)



if __name__=="__main__":
     main()




     

