import argparse
import json
import logging
from os.path import exists
import sys
from timeit import default_timer as timer
import hashlib

__author__ = "Jouni Lehto"
__versionro__="0.1.3"

#Global variables
args = ""

def getAnalysisIssues():
    previewFileName = args.inputFile
    if ( exists(previewFileName) ):
        previewData = json.load(open(previewFileName, "r"))
        if previewData:
            issues = previewData["issues"]
            return issues
    else:
        logging.error(f'File: {previewFileName} not found!')

def getSarifJsonHeader():
    return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

def getResults():
    cov_issues = getAnalysisIssues()
    if cov_issues:
        results = {}
        sarifIssues = []
        rules = []
        ruleIds = []
        for cov_issue in cov_issues:
            ruleId = f'{cov_issue["checkerName"]}/{cov_issue["type"]}/{cov_issue["subtype"] if "subtype" in cov_issue else "_"}/{cov_issue["code-language"]}'
            sarifIssue = {"ruleId":ruleId}
            if not ruleId in ruleIds:
                rule = {"id":ruleId, "shortDescription":{"text":cov_issue['checkerProperties']['subcategoryShortDescription']}, 
                    "fullDescription":{"text":f'{cov_issue["checkerProperties"]["subcategoryLongDescription"] if cov_issue["checkerProperties"]["subcategoryLongDescription"] else "N/A"}'},
                    "defaultConfiguration":{"level":nativeSeverityToLevel(cov_issue['checkerProperties']['impact'].lower())}}
                rules.append(rule)
                ruleIds.append(ruleId)
            messageText = ""
            remediationText = ""
            mainlineNumber = 1
            locations = []
            for event in sorted(cov_issue['events'], key=lambda x: x['eventNumber']):
                lineNumber = 1
                if event["lineNumber"]: 
                    lineNumber = int(event["lineNumber"])
                locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": event["filePathname"][len(args.strip_path)+1::].replace("\\","/")},"region":{"startLine": lineNumber}}, 
                    "message" : {"text": f'Event Set {event["eventTreePosition"]}: {event["eventDescription"]}'}}})
                if event['main']: 
                    messageText = event['eventDescription']
                    mainlineNumber = event['lineNumber']
                if event['events'] and len(event['events']) > 0:
                    for subevent in sorted(event['events'], key=lambda x: x['eventNumber']):
                        subLineNumber = 0
                        if subevent["lineNumber"]: 
                           subLineNumber = int(subevent["lineNumber"])
                        locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": subevent["filePathname"][len(args.strip_path)+1::].replace("\\","/")},"region":{"startLine":subLineNumber}}, 
                            "message" : {"text": f'Event #{subevent["eventTreePosition"]}: {subevent["eventDescription"]}'}}})
                if event['remediation']: remediationText = event['eventDescription']
            if not remediationText == "":
                messageText += f'\nRemediation Advice: {remediationText}'
            sarifIssue['message'] = {"text": cov_issue["checkerName"] + ":" + messageText}
            sarifIssue['locations'] = [{"physicalLocation":{"artifactLocation":{"uri":cov_issue["mainEventFilePathname"][len(args.strip_path)+1::].replace("\\","/")},"region":{"startLine": int(mainlineNumber)}}}]
            sarifIssue['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f"{cov_issue['mergeKey']}").encode(encoding='UTF-8')).hexdigest()}
            codeFlowsTable, loctionsFlowsTable = [], []
            threadFlows, loctionsFlows = {}, {}
            loctionsFlows['locations'] = locations
            loctionsFlowsTable.append(loctionsFlows)
            threadFlows['threadFlows'] = loctionsFlowsTable
            codeFlowsTable.append(threadFlows)
            sarifIssue['codeFlows'] = codeFlowsTable
            sarifIssues.append(sarifIssue)
        results['results'] = sarifIssues
        return results, rules
    else:
        logging.info(f'No issues found!')
        return {},{}

def getSarifJsonFooter(toolDriverName, rules):
    return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":__versionro__,"organization":"Synopsys","rules":rules}}

def nativeSeverityToLevel(argument): 
    switcher = { 
        "audit": "warning", 
        "high": "error", 
        "low": "note", 
        "medium": "warning"
    }
    return switcher.get(argument, "warning")

def writeToFile(coverityFindingsInSarif):
    f = open(args.outputFile, "w")
    f.write(json.dumps(coverityFindingsInSarif, indent=3))
    f.close()

#
# Main mathod
#
if __name__ == '__main__':
    start = timer()
    result = False
    parser = argparse.ArgumentParser(
        description="Coverity JSON to SARIF formatter"
    )
    #Parse commandline arguments
    parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
    parser.add_argument('--inputFile', help="Filename with path which will contain the local scan findings \
        (Coverity Analysis results should be provided in the \"v10\" JSON format produced by the --json-output-v10 option \
            of the cov-format-errors command or the cov-run-desktop command.), example: /tmp/coverityFindings.json", required=False, default="coverity_results-v10.json")
    parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/coverityFindings.sarif.json", required=False, default="coverity_results.sarif.json")
    parser.add_argument('--url', help="Coverity Connect server url", default="")
    parser.add_argument('--strip_path', help="Full path to where source folders will start. This path will be removed from the code locations", default="")
    
    args = parser.parse_args()
    #Initializing the logger
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=args.log_level)
    #Printing out the version number
    logging.info("Coverity JSON to SARIF formatter version: " + __versionro__)
    sarif_json = getSarifJsonHeader()
    results, rules = getResults()
    results['tool'] = getSarifJsonFooter("Coverity", rules)
    runs = []
    runs.append(results)
    sarif_json['runs'] = runs
    writeToFile(sarif_json)
    end = timer()
    logging.info(f"Creating SARIF format took: {end - start} seconds.")
    logging.info("Done")
