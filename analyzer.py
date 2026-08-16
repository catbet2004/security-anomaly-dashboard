import numpy as np
import pandas as pd


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

     #detects amount of failures from an IP
     analysis=analysis.sort_vals("timestamp")

     #failed attempts
     logs_failed=analysis[analysis["status"]=="failed"].copy()

     if not logs_failed.empty:
          logs_failed["failed_5min"]=(
               logs_failed
               .set_index("timestamp")
               .groupby("ip_address")["failed"]
               .rolling("5min")
               .sum()
               .reset_index(level=0,drop=True)
          )
          failure_sum=(
               logs_failed.groupby("ip_address")["failed_5min"].max().reset_index()
          )
          failure_sum=failure_sum.rename(
               cols={"failed_5min" : "max_failed_5min"}
          )
     else:
          failure_sum=pd.DataFrame(
               cols=["ip_address", "max_failed_5min",
               ]
          )

     ip_sum= (
          analysis.groupby(["ip_address","date"],as_index=False).agg(
               total_attempts=("status", "size"),
               failed_attempts=("failed", "sum"),
               unique_users=("username","nunique"),
               off_time_attempts=("off_hours", "sum"),
          )
     )
     #attempt info
     ip_sum=ip_sum.merge(
          failure_sum,
          on="ip_address",
          how="left",
     )
     ip_sum["max_failed_5min"]=(ip_sum["max_failed_5min"].fillna(0))

     ip_sum["failure_rate"]=(
          ip_sum["failed_attempts"]/ip_sum["total_attempts"]*100
     ).round(1)

     #brute-force detection
     ip_sum["brute_force_potential"]=(ip_sum["max_failed_5min"]>=5&(ip_sum["unique_users"]<=2))
     #password spaying detection
     ip_sum["password_spay_potential"]=(ip_sum["failed_attempts"]>=5&(ip_sum["unique_users"]>=5))

     return ip_sum

def non_neg_score(values: pd.Series)->np.ndarray:
     nums=values.to_numpy(dtype=float)
     avg=np.mean(nums)
     std=np.std(nums)

     if std==0:
          return np.zeros(len(nums))
     score=(nums-avg)/std

     return np.maximum(score,0)

def anom_score(ip_sum: pd.DataFrame)-> pd.DataFrame:
     score=ip_sum.copy()
     if score.empty:
          score["anomaly_score"]=pd.Series(dtype=float)
          score["suspicious"]=pd.Series(dtype=bool)
          score["risk_level"]=pd.Series(dtype="string")
          return score

     fails_score=non_neg_score(score["failed_attempts"])
     sus_users=non_neg_score(score["unique_users"])
     fast_score=non_neg_score(score["max_failed_5min"])
     sus_hour_score=non_neg_score(score["off_hour_attempts"])

     #total score
     score["anomaly_score"]=(
          fails_score+(sus_users*0.75)+fast_score+(sus_hour_score*0.50).round(2)
     )

     score.loc[score["brute_force_potential"], "anomaly_score"]+=1.0

     score.loc[score["password_spray_potential"], "anomaly_score"]+=1.0

     score["suspicious"]=(score["anomaly_score"]>=1.5)

     conditions=[
          score["anomaly_score"]>=3.0,
          score["anomaly_score"]>=1.5,
     ]
     lvls=[
          "High",
          "Medium",
     ]
     score["risk_level"]=np.select(
          conditions,
          lvls,
          default="Low",
     )

     #most sus goes first
     return score.sort_values(
          by="anomaly_score",
          ascending=False,
     ).reset_index(drop=True)






     

