policies = {
    "canIpForward" : "4.6 Ensure That IP Forwarding Is Not Enabled on Instances",
    "externalIp" : "4.9 Ensure That Compute Instances Do Not Have Public IP Addresses ",
    "bucketPublicAccess" : "5.1 Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
    "uniformBucketLevelAccess" : "5.2 Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled",
    "skip_show_database" : "6.1.2 Ensure Skip_show_database Database Flag for Cloud SQL MySQL Instance Is Set to On",
    "local_infile" : "6.1.3 Ensure That the Local_infile Database Flag for a Cloud SQL MySQL Instance Is Set to Off",
    "datasetkmsKeyName":"Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets",
    "tablekmsKeyName":"7.2 Ensure That All BigQuery Tables Are Encrypted With Customer Managed Encryption Key (CMEK)"

}

violation = {
    "canIpForward" : True,
    "externalIp" : True,
    "bucketPublicAccess" : True,
    "uniformBucketLevelAccess" : False,
    "skip_show_database" : "off",
    "local_infile" : "on",
    "datasetkmsKeyName" : False,
    "tablekmsKeyName" : False

}