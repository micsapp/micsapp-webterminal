#!/bin/bash
# Create a new system user for web terminal access.
# Auto-detects macOS (dscl) vs Linux (useradd).

read -p "Username: " USERNAME
read -p "Full Name: " FULLNAME
read -s -p "Password: " PASSWORD
echo

if [ "$(uname -s)" = "Darwin" ]; then
  # macOS: use Directory Service
  LAST_UID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1)
  NEW_UID=$((LAST_UID + 1))

  echo "Creating macOS user '$USERNAME' (UID: $NEW_UID)..."

  sudo dscl . -create /Users/$USERNAME
  sudo dscl . -create /Users/$USERNAME UserShell /bin/bash
  sudo dscl . -create /Users/$USERNAME RealName "$FULLNAME"
  sudo dscl . -create /Users/$USERNAME UniqueID $NEW_UID
  sudo dscl . -create /Users/$USERNAME PrimaryGroupID 20
  sudo dscl . -create /Users/$USERNAME NFSHomeDirectory /Users/$USERNAME
  sudo mkdir -p /Users/$USERNAME
  sudo chown $USERNAME:staff /Users/$USERNAME
  sudo dscl . -passwd /Users/$USERNAME "$PASSWORD"
else
  # Linux: use useradd + chpasswd
  echo "Creating Linux user '$USERNAME'..."

  sudo useradd -m -s /bin/bash -c "$FULLNAME" "$USERNAME"
  echo "$USERNAME:$PASSWORD" | sudo chpasswd
fi

echo "Done. User '$USERNAME' created."
