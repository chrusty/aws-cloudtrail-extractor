package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

var (
	awsRegion = flag.String("region", "ap-southeast-2", "AWS region")
	startTime = flag.Int64("start", 1577836800, "Earliest event (unixtime)")
	endTime   = flag.Int64("end", 1593561600, "Latest event (unixtime)")
)

func main() {

	flag.Parse()

	// CloudTrail service:
	cloudTrail := cloudtrail.New(session.Must(session.NewSession(aws.NewConfig().WithRegion(*awsRegion))))

	// Define request parameters:
	lookupEventsInput := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int64(50),
		StartTime:  aws.Time(time.Unix(*startTime, 0)),
		EndTime:    aws.Time(time.Unix(*endTime, 0)),
	}

	// Call CloudTrail asking for more and more events:
	for {
		lookupEventsOutput, err := cloudTrail.LookupEvents(lookupEventsInput)
		if err != nil {
			log.Fatalf("Error calling AWS CloudTrail: %v", err)
		}

		// Print the events:
		for _, event := range lookupEventsOutput.Events {
			fmt.Println(event.String())
		}

		// Break from the loop if we don't have a nextToken (means we must have had all the events):
		if lookupEventsOutput.NextToken == nil {
			break
		}

		// Assume the nextToken:
		lookupEventsInput.NextToken = lookupEventsOutput.NextToken
	}
}
