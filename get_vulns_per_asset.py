import requests
import json
from auth_file import NexposeAuth

# for suppressing the waring regarding using insecure switch in 'requests'
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    AssetNames = OpenFile("AssetList.txt")

    ActiveAssets, InactiveAssets = ParseAssets(AssetNames)
    VulnDict = GetVulnsPerAsset(ActiveAssets)



    print("\n\nVulnerabilities:")
    DisplayVulns(VulnDict)
    print("\n\nActive Assets in Nexpose:")
    DisplayAssets(ActiveAssets)
    print("\n\nAssets Missing from Nexpose:")
    DisplayAssets(InactiveAssets)


def OpenFile(FileName):
    with open(FileName, 'r') as TextFile:
        Data = TextFile.readlines()
    return Data



def ParseAssets(AssetNames):
    ActiveAssets = []
    InactiveAssets = []
    for Asset in AssetNames:
        AssetName = Asset.lower().strip()
        AssetStatus = LookupAsset(AssetName)
        try:
            ActiveAssets.append(AssetStatus["Active"])
        except:
            InactiveAssets.append(AssetStatus["Inactive"])

    return ActiveAssets, InactiveAssets


def LookupAsset(AssetName):
    AssetState = {}

    URL = "https://<servername>:3780/api/3/assets/search"

    SearchBody = {
      "match": "all",
      "filters": [
         {"field": "host-name", "operator": "contains", "value": AssetName}
      ]
    }

    Results = requests.post(URL, headers={'Authorization': 'Basic {}'.format(NexposeAuth)},
                            verify=False, json=SearchBody)

    NexposeAssetList = Results.json()
    #NexposeAssetList = Results

    try:
        #AssetState["Active"] = NexposeAssetList["resources"][0]["hostName"]
        AssetHostName = NexposeAssetList["resources"][0]["hostName"]
        AssetID = NexposeAssetList["resources"][0]["id"]
        AssetState["Active"] = [AssetHostName, AssetID]
    except:
        AssetState["Inactive"] = AssetName
        #ResourcesFound = NexposeAssetList["page"]["totalResources"]
        #ErrorCode = "Resources Found = {}".format(ResourcesFound)
        #Error(ErrorCode)

    return AssetState



def GetVulnsPerAsset(ActiveAssets):

    AssetDatabase = {}
    for AssetData in ActiveAssets:
        VulnList = []
        AssetID = AssetData[1]
        AssetHostName = AssetData[0]
        URL = "https://<servername>:3780/api/3/assets/{}/vulnerabilities".format(AssetID)

        Results = requests.get(URL, headers={'Authorization': 'Basic {}'.format(NexposeAuth)},
                                verify=False)
        VulnData = Results.json()

        Counter = 0
        for Entry in VulnData["resources"]:
            VulnList.append(VulnData["resources"][Counter]["id"])
            Counter += 1
        AssetDatabase[AssetHostName] = VulnList

    return AssetDatabase


def DisplayAssets(AssetArray):
    for Asset in AssetArray:
        print(Asset)


def DisplayVulns(VulnDict):
    for key, value in VulnDict.items():
        print("\nAsset: {}".format(key))
        for i in value:
            print("\t{}".format(i))
        print("\n")

def Error(ErrorCode):
    print("ERROR: {}".format(ErrorCode))
    exit(1)


if __name__ == "__main__":
    print("starting...\n")
    main()
    print("\n...ending")
