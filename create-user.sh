#!/bin/bash
# Create a new macOS user for web terminal testing

read -p "Username: " USERNAME
read -p "Full Name: " FULLNAME
read -s -p "Password: " PASSWORD
echo

# Find next available UID
LAST_UID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1)
NEW_UID=$((LAST_UID + 1))

echo "Creating user '$USERNAME' (UID: $NEW_UID)..."

sudo dscl . -create /Users/$USERNAME
sudo dscl . -create /Users/$USERNAME UserShell /bin/bash
sudo dscl . -create /Users/$USERNAME RealName "$FULLNAME"
sudo dscl . -create /Users/$USERNAME UniqueID $NEW_UID
sudo dscl . -create /Users/$USERNAME PrimaryGroupID 20
sudo dscl . -create /Users/$USERNAME NFSHomeDirectory /Users/$USERNAME
sudo mkdir -p /Users/$USERNAME
sudo chown $USERNAME:staff /Users/$USERNAME
sudo dscl . -passwd /Users/$USERNAME "$PASSWORD"

echo "Done. User '$USERNAME' created."
echo "You can now log in at https://micsmac-ssh.micstec.com with these credentials."
