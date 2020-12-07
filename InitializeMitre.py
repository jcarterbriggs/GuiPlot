#!/usr/bin/env python

import json
import urllib.request
import operator
import os
import pandas as pd

APTGroup = "APT29"

companies = [#"Bitdefender",
             "CrowdStrike",
             "Cybereason",
             #"Cycraft",
             #"Cylance",
             #"Elastic",
             #"F-Secure",
             "FireEye",
             #"GoSecure",
             #"HanSight",
             #"Kaspersky",
             #"Malwarebytes",
             #"McAfee",
             #"Microsoft",
             #"PaloAltoNetworks",
             #"ReaQta",
             #"Secureworks",
             #"SentinelOne",
             "Symantec",
             #"TrendMicro",
             #"VMware"
             ]
file_directory = "./json_files/"
FullResults = {}
dfResults = pd.DataFrame()

URLPrefix = "https://attackevals.mitre-engenuity.org/"
URLSuffix = ".1_Results.json"
Debug = True
Download = True




def downloadFiles():
    if Download:

        if Debug:
            print("Downloading Files")
        if not os.path.isdir(file_directory):
            if Debug:
                print("creating json directory")
            os.mkdir(file_directory)
        # download all the files and enter them into the "FullResults" dictionary
        for Comp in companies:
            FulURL = URLPrefix + Comp + ".1." + APTGroup + URLSuffix
            if Debug:
                print("Downloading from URL: " + FulURL)
            OutputFile = file_directory + Comp + ".json"
            urllib.request.urlretrieve(FulURL, OutputFile)


def createDictionary():
    if Debug:
        print("Creating Dictionary from json files")
    for Comp in companies:
        ReadFile = file_directory + Comp + ".json"
        with open(ReadFile) as Company:
            if Debug:
                print("loading file " + ReadFile)
            FullResults[str(Comp)] = json.load(Company)


# go through each company and count the detections and failures
def createDataFrame():
    columns = (
    "Company", "TechniqueId", "TechniqueName", "TacticId", "Criteria", "TacticName", "StepNumber", "DetectionIndex",
    "MainDetectionType", "ModifierCount", "ModifierDetectionType", "SubStep")
    newDF = pd.DataFrame(columns=columns)
    if Debug:
        print("Analyzing Results")
    for Comp in companies:
        # load each Technique
        for Tech in FullResults[Comp]['Techniques']:
            # load each Step
            TechniqueID = Tech['TechniqueId']
            TechniqueName = Tech['TechniqueName']
            TacticId = Tech['Tactics'][0]['TacticId']
            TacticName = Tech['Tactics'][0]['TacticName']
            StepCount = 0
            for Step in Tech['Steps']:
                # Load each Detection
                # Criteria = Step['Criteria']
                SubStep = Step['SubStep']
                DetectCount = 0
                for Detect in Step['Detections']:
                    DetectionType = Detect['DetectionType']
                    dfNew = {'Company': Comp,
                             'TechniqueId': TechniqueID,
                             'TechniqueName': TechniqueName,
                             'TacticId': TacticId,
                             'TacticName': TacticName,
                             # 'Criteria' : Criteria,
                             'StepNumber': StepCount,
                             'DetectionIndex': DetectCount,
                             'ModifierDetectionType': "",
                             'MainDetectionType': DetectionType,
                             'SubStep': SubStep
                             }

                    # iterate through modifiers if there are any
                    if Detect['Modifiers']:
                        ModCount = 0
                        for Mod in Detect['Modifiers']:
                            dfNew['ModifierDetectionType'] = Mod
                            ModCount += 1
                    newDF = newDF.append(dfNew, ignore_index=True)
                    DetectCount += 1
                StepCount += 1
    return newDF