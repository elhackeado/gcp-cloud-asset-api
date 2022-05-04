from slack_sdk.webhook import WebhookClient
import datetime

x = datetime.datetime.now()

timestamp = x.strftime("%b,%d %Y %a %H:%M:%S")
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
					"text": "*Violation Found:*\n0"
				},
				{
					"type": "mrkdwn",
					"text": "*Scan Completed At:*\n" + timestamp
				}
			]
		}
    ]
)