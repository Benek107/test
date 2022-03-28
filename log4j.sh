#!/bin/zsh
###############################################################################
# Hitachi Vantara Jamf Shell Script
# Copyright 2020 Hitachi Vantara, all rights reserved
#
# Author Name: Weinkauf, Chris
# Author Date: Apr 17 2020
# Purpose: Finds legacy apps on the system and in the users home directory
#
#
# Change Log:
# Apr 17 2020, Weinkauf, Chris <chris.weinkauf@hitachivantara.com>
# - Initial Creation
###############################################################################

#-------------------
# Parse standard arguments and set common variables
#-------------------
__TARGET_VOL="$1"
__COMPUTER_NAME="$2"
__USERNAME="$3"
__SERIAL_NUMBER="$(/usr/sbin/ioreg -c IOPlatformExpertDevice -d 2 | /usr/bin/awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}')"
__CONSOLE_USER="$(/usr/bin/stat -f %Su /dev/console)"
__JAMF_HELPER="/Library/Application Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper"
__JAMF_BIN="/usr/local/jamf/bin/jamf"

#-------------------
# Variables
#-------------------
LIST="$(/usr/bin/mdfind -name "log4j-core-1. OR log4j-core-2." c -onlyin /Applications/ -onlyin /Users -onlyin /usr/ | grep -v '/Outlook/' | grep -v '2.17' | grep -v '2.18')"
HOME_DIRECTORY="$(/usr/bin/dscl . -read /Users/$__CONSOLE_USER NFSHomeDirectory | awk '{print $2}')"
OUTPUT_LOCATION="$HOME_DIRECTORY/Desktop/Log4J-Report-$(date +"%Y-%m-%d%n_%H%M%S").csv"

#------------------------------------------------------------------------------
# Start Script
#------------------------------------------------------------------------------
echo "INFO: Started run at $(date)"

IFS=$'\n'

echo "Creating report header..."

# Build report header by echoing to output files
echo "Report Generated: $(date)" > "$OUTPUT_LOCATION"
echo "" >> "$OUTPUT_LOCATION"
echo "Apache Log4j2 versions 1.X" >> "$OUTPUT_LOCATION"
echo "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration." >> "$OUTPUT_LOCATION"
echo "The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228." >> "$OUTPUT_LOCATION"
echo "" >> "$OUTPUT_LOCATION"
echo "Apache Log4j2 versions 2.X" >> "$OUTPUT_LOCATION"
echo "Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack where an attacker with permission to modify the logging configuration file can construct a malicious configuration using a JDBC Appender with a data source referencing a JNDI URI which can execute remote code." >> "$OUTPUT_LOCATION"
echo "" >> "$OUTPUT_LOCATION"
echo "How to FIX:" >> "$OUTPUT_LOCATION"
echo "Customers are required to upgrade their Log4j to the minimum version 2.17.1" >> "$OUTPUT_LOCATION"
echo "For additional details see https://logging.apache.org/log4j/2.x/security.html" >> "$OUTPUT_LOCATION"
echo "" >> "$OUTPUT_LOCATION"
echo "Found Apache Log4j version 1.X and 2.X" >> "$OUTPUT_LOCATION"

echo "Done."
echo "Adding discovered line items..."

# Loop through the items found in the list variable
while read -r ITEM; do
    # ITEM_NAME=$(/usr/bin/defaults read "$ITEM/Contents/Info.plist" CFBundleName)
    # ITEM_VERSION=$(/usr/bin/defaults read "$ITEM/Contents/Info.plist" CFBundleVersion)
    # ITEM_IDENTIFIER=$(/usr/bin/defaults read "$ITEM/Contents/Info.plist" CFBundleIdentifier)

    echo "$ITEM" >> "$OUTPUT_LOCATION"

done <<< "$LIST"

# Set the permissions so the logged in user can read the file
echo "Updating permissions for $OUTPUT_LOCATION"
/usr/sbin/chown "$__CONSOLE_USER" "$OUTPUT_LOCATION"
/bin/chmod o+rw "$OUTPUT_LOCATION"

# Use AppleScript to gracefully launch the file for the user in the default app (most likely Excel, possibly Numbers)
echo "Opening the report for the user..."
/usr/bin/osascript -e 'tell application "Finder" to open POSIX file "'"$OUTPUT_LOCATION"'"'

# Check for errors opening the file
if [[ "$?" != "0" ]]; then
    echo "ERROR: Failed to open $OUTPUT_LOCATION"
    exit 2
fi

#------------------------------------------------------------------------------
# End Script
#------------------------------------------------------------------------------
echo "INFO: Completed at $(date)"
exit 0
