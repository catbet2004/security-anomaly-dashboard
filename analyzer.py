import numpy as np
import pandas as pd
import streamlit as st

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
     clean["timestamp"]=pd.to_datetime(clean["timestamp"], errors="coerce") #invalid changed to NaT

     clean=clean.dropna(subset=[
          "timestamp", "username", "ip_address", "status"
     ])

     clean=clean[clean["status"].isin(["success", "failed"])]

     clean=clean.reset_index(drop=True)

     return clean


     

def main()-> None:
    try:
          logs=load_logs("some_logs.csv")
          cleaned_logs=clean_logs(logs)
    except ValueError as error:
         print(f"Error: {error}")
         return

    print ("Original data:")
    print(logs)

    print("\nCleaned data:")
    print(cleaned_logs)

    print("\nNumber of valid records:")
    print(len(cleaned_logs))

    print("\nColumn data types:")
    print(cleaned_logs.dtypes)

if __name__=="__main__":
     main()




     

