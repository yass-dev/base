TITLE=$1
ACTOR=$2

echo "#######[STEP-1]#######"
echo "Prepare to run: $TITLE"

echo "#######[STEP-2]#######"
echo "Check the actor is allowed to execute command"
ALLOWED_ACTORS=("tr0l")

# Create a space-separated string of allowed values for comparison
if [[ " ${ALLOWED_STRINGS[@]} " =~ " $ACTOR " ]]; then
echo "User is allowed to run script"
else
echo "User is NOT allowed to run script"
fi

echo "#######[STEP-3]#######"
echo "Check the command start with gh and save for later use"
if [[ "$COMMAND" == gh\ * ]]; then
echo "Command is valid !"
echo "The flag is $FLAG"
else
echo "Command NOT is valid"
fi