from google.cloud import asset_v1
import json
import proto
from slack_sdk.webhook import WebhookClient
import datetime

headers = {"Authorization" : "Bearer token"}
project_id = 'lively-encoder-347305'

policies = {
    "defaultNetwork" : "3.1 Ensure That the Default Network Does Not Exist in a Project",
    "openSSHRule" : "3.6 Ensure That SSH Access Is Restricted From the Internet",
    "openRDPRule" : "3.7 Ensure That RDP Access Is Restricted From the Internet",
    "canIpForward" : "4.6 Ensure That IP Forwarding Is Not Enabled on Instances",
    "externalIp" : "4.9 Ensure That Compute Instances Do Not Have Public IP Addresses ",
    "bucketPublicAccess" : "5.1 Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
    "uniformBucketLevelAccess" : "5.2 Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled",
    "skip_show_database" : "6.1.2 Ensure Skip_show_database Database Flag for Cloud SQL MySQL Instance Is Set to On",
    "local_infile" : "6.1.3 Ensure That the Local_infile Database Flag for a Cloud SQL MySQL Instance Is Set to Off",
    "datasetkmsKeyName":"7.3 Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets",
    "tablekmsKeyName":"7.2 Ensure That All BigQuery Tables Are Encrypted With Customer Managed Encryption Key (CMEK)"
    

}

violation = {
    "defaultNetwork" : True,
    "openSSHRule" : True,
    "openRDPRule" : True,
    "canIpForward" : True,
    "externalIp" : True,
    "bucketPublicAccess" : True,
    "uniformBucketLevelAccess" : False,
    "skip_show_database" : "off",
    "local_infile" : "on",
    "datasetkmsKeyName" : False,
    "tablekmsKeyName" : False

}
violationslist = []

def getAssets(asset_type):
    #asset_types = "compute.googleapis.com/Instance"
    # ["storage.googleapis.com/Bucket","bigquery.googleapis.com/Table"]'
    page_size = 1
    # 1000 (both inclusively)'
    content_type = asset_v1.ContentType.RESOURCE

    project_resource = "projects/{}".format(project_id)
    client = asset_v1.AssetServiceClient()

    # Call ListAssets v1 to list assets.
    response = client.list_assets(
        request={
            "parent": project_resource,
            "read_time": None,
            "asset_types": [asset_type],
            "content_type": content_type,
            "page_size": page_size,
        }
    )
    return response


def getVMViolations():
    response = getAssets("compute.googleapis.com/Instance")
    print("+++++++++++  Google Compute Engine  ++++++++++++++")
    for asset in response:
        resourcename = asset.resource.data.get("name")
        print("[ VM Name -->  ", resourcename,"]")
        asset_json = json.loads(proto.Message.to_json(asset))
        #canIpForward = asset.resource.data.get("canIpForward")
        canIpForward = asset_json["resource"]["data"]["canIpForward"]
        externalIp = True
        for i in asset_json["resource"]["data"]["networkInterfaces"]:
            try:
                print(i["accessConfigs"])
            except KeyError as e:
                externalIp = False
                break
        print("canIpForward :",canIpForward)
        print("externalIp :", externalIp)
        checkViolation("canIpForward", canIpForward, resourcename, "VM")
        checkViolation("externalIp", externalIp, resourcename, "VM")
        


def getBucketViolations():
    import requests
    x = requests.get("https://www.googleapis.com/storage/v1/b?project=lively-encoder-347305", headers=headers)
    print("+++++++++++   Google Cloud Storage Bucket  ++++++++++++++")
    #print(x.json())
    if(len(dict(x.json()))>1 and x.status_code==200):
        for i in x.json()['items']:
            bucket_name = i['id'].strip()
            print("[ BUCKET NAME --> ", bucket_name , "]")
            uniformBucketLevelAccess = i["iamConfiguration"]["uniformBucketLevelAccess"]["enabled"]
            print("uniformBucketLevelAccess :", uniformBucketLevelAccess )
            checkViolation("uniformBucketLevelAccess", uniformBucketLevelAccess, bucket_name, "GCS Bucket")
            bucketPublicAccess = False
            u = requests.get("https://www.googleapis.com/storage/v1/b/"+bucket_name+"/iam", headers=headers)
            for j in u.json()['bindings']:
                if "allUsers" in j['members'] or 'allAuthenticatedUsers' in j['members']:
                    bucketPublicAccess = True
            print("bucketPublicAccess :", bucketPublicAccess, "\n")
            checkViolation("bucketPublicAccess", bucketPublicAccess, bucket_name, "GCS Bucket")

def getNetworkViolations():
    import requests
    #x = requests.get("https://www.googleapis.com/storage/v1/b?project=lively-encoder-347305", headers=headers)    
    print("+++++++++++   Google VPC  ++++++++++++++")
    #response = requests.get("https://compute.googleapis.com/compute/v1/projects/"+ project_id +"/global/networks", )
    #print(response.json())
    response = getAssets("compute.googleapis.com/Network")
    for asset in response:
        print("[ Network Name -->  ", asset.resource.data.get("name"),"]")
        asset_json = json.loads(proto.Message.to_json(asset))
        #canIpForward = asset.resource.data.get("canIpForward")
        resourcename = asset_json["resource"]["data"]["name"]
        defaultNetwork = "default" in resourcename
        print("defaultNetwork :", defaultNetwork)
        checkViolation("defaultNetwork", defaultNetwork, resourcename, "VPC")
    response = getAssets("compute.googleapis.com/Firewall")
    for asset in response:
        resourcename = asset.resource.data.get("name")
        print("[ Firewall Rule Name -->  ", resourcename,"]")
        asset_json = json.loads(proto.Message.to_json(asset))
        rule = asset_json['resource']['data']
        openSSHRule = False
        openRDPRule = False
        if "0.0.0.0/0" in rule['sourceRanges'] and 'INGRESS' in rule['direction']:
            print(rule['allowed'])
            for i in rule['allowed']:
                if 'tcp' in i['IPProtocol'] or 'all' in i['IPProtocol']:
                    if '22' in i['ports']:
                        openSSHRule = True
                    if '3389' in i['ports']:
                        openRDPRule = True
                    for p in i['ports']:
                        if len(p.split('-')) > 1:
                            if int(p.split('-')[0])<=22 and int(p.split('-')[1])>=22:
                                openSSHRule = True
                            if int(p.split('-')[0])<=3389 and int(p.split('-')[1])>=3389:
                                openRDPRule = True
        checkViolation("openSSHRule", openSSHRule, resourcename, "F/W Rule")
        checkViolation("openRDPRule", openRDPRule, resourcename, "F/W Rule")
        

def getDBViolations():
    print("+++++++++++   Google Cloud SQL  ++++++++++++++")
    response = getAssets("sqladmin.googleapis.com/Instance")
    for asset in response:
        asset_json = json.loads(proto.Message.to_json(asset))
        resourcename = asset.resource.data.get("name")
        print("[ Cloud SQL Intance Name -->  ", resourcename ,"]")
        skip_show_database = 'off'
        local_infile = 'on'
        try:
            for i in asset_json['resource']['data']['settings']['databaseFlags']:
                if i['name']=='skip_show_database' and  i['value']=='on':
                    skip_show_database = 'on'
                elif i['name']=='local_infile' and  i['value']=='off':
                    local_infile = 'off'
        except KeyError as e:
            pass
        print('skip_show_database :', skip_show_database)
        print('local_infile :', local_infile)
        checkViolation("skip_show_database", skip_show_database, resourcename, "MYSQL DB")
        checkViolation("local_infile", local_infile, resourcename, "MYSQL DB")

def getBQViolations():
    print("+++++++++++   Google Big Query  ++++++++++++++")
    response = getAssets("bigquery.googleapis.com/Dataset")
    for asset in response:
        asset_json = json.loads(proto.Message.to_json(asset))
        datasetkmsKeyName = False
        resourcename = asset_json['resource']['data']['datasetReference']['datasetId']
        print("[ Big Query Dataset Name -->  ", resourcename,"]")
        try:
            if asset_json['resource']['data']['defaultEncryptionConfiguration']['kmsKeyName'] != '':
                datasetkmsKeyName = True
        except KeyError as e:
            pass
        print("datasetkmsKeyName :", datasetkmsKeyName)
        print("")
        checkViolation("datasetkmsKeyName", datasetkmsKeyName, resourcename, "BQ Dataset")
        
    print("\n")
    response = getAssets("bigquery.googleapis.com/Table")
    for asset in response:
        asset_json = json.loads(proto.Message.to_json(asset))
        resourcename = asset_json['resource']['data']['tableReference']['tableId']
        print("[ Big Query Table Name -->  ", resourcename,"]")
        tablekmsKeyName = False
        try:
            if asset_json['resource']['data']['encryptionConfiguration']['kmsKeyName'] != '':
                tablekmsKeyName = True
        except KeyError as e:
            pass
        print("tablekmsKeyName :", tablekmsKeyName)
        print("")
        checkViolation("tablekmsKeyName", tablekmsKeyName, resourcename, "BQ Table")

def checkViolation(key, value, resourcename, type):
    if value == violation[key]:
        violationslist.append({
            "resource_name":resourcename, 
            "violation_key":key,
            "violation_key_value": value,
            "resource_type" : type
            })

def listViolations():
    print("+++++++++++++++++++++++++++++   LISTING VIOLATIONS   +++++++++++++++++++++++++++++")
    print("BENCHMARK ->", "CIS Google Cloud Platform Foundation")
    print("BENCHMARK VERSION ->","v1.3.0")
    print("BENCHMARK RELEASE DATE ->", "03-31-2022","\n")

    print(" %-20s %-20s %-30s %-20s %10s" % ("RESOURCE NAME", "RESOURCE TYPE" ,"VIOLATION KEY", "VIOLATION VALUE", "GCP-CIS POLICY"))
    for i in violationslist:
        print(" %-20s %-20s %-30s %-20s %10s" % (i['resource_name'], i['resource_type'], i['violation_key'], i['violation_key_value'], policies[i['violation_key']].split(" ")[0]))
    print("\nTotal Violations Found ---> ", len(violationslist), " \n")
    #notify(len(violationslist))

def notify(nviolations):
    x = datetime.datetime.now()
    timestamp = x.strftime("%b,%d %Y %a %H:%M:%S %z")
    print(timestamp)
    url = "https://hooks.slack.com/services/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"
    webhook = WebhookClient(url)

    response = webhook.send(
        text="GCP asset scan completed",
        blocks=[
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Benchmark Scan Name:*\nGCP-CIS FOUNDATIONS"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Benchmark Version:*\nv1.3.0"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Benchmark Release Date:*\n 31/03/2022"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Violation Found:*\n" + str(nviolations)
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Scan Completed At:*\n" + timestamp
                    }
                ]
            }
        ]
    )

if __name__ == "__main__":
    getVMViolations()
    #getBucketViolations()  
    getNetworkViolations()
    #getDBViolations()
    #getBQViolations()
    listViolations()