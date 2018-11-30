import requests
import json
from auth_file import NexposeAuth

# for suppressing the waring regarding using insecure switch in 'requests'
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    AssetNames = OpenFile("AssetList.txt")

    ActiveAssets, InactiveAssets = ParseAssets(AssetNames)

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
        AssetState["Active"] = NexposeAssetList["resources"][0]["hostName"]
    except:
        AssetState["Inactive"] = AssetName
        #ResourcesFound = NexposeAssetList["page"]["totalResources"]
        #ErrorCode = "Resources Found = {}".format(ResourcesFound)
        #Error(ErrorCode)

    return AssetState


def DisplayAssets(AssetArray):
    for Asset in AssetArray:
        print(Asset)

def Error(ErrorCode):
    print("ERROR: {}".format(ErrorCode))
    exit(1)


if __name__ == "__main__":
    print("starting...\n")
    main()
    print("\n...ending")
