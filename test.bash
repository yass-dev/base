ACTOR=$1

echo "'${ALLOWED_STRINGS[@]}'"
if [[ " ${ALLOWED_STRINGS[@]} " =~ " $ACTOR " ]]; then
echo "User is allowed to run script"
else
echo "User is NOT allowed to run script"
fi