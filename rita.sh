#!/usr/bin/env bash

# --rm removes the container after it's run rather than leaving it around
DOCKER_ARGS=("--rm")
RITA_ARGS=()
LOGS=""
DOCKER_CONFIG="$HOME/.docker/config.json"
DOCKER_DAEMON="$HOME/.docker/daemon.json"
DOCKER_SOCKET="/var/run/docker.sock"

IS_IMPORT_COMMAND="false"

require_sudo () {
     if [ "$EUID" -eq 0 ]; then
        SUDO=""
        SUDO_E=""
        return 0
    fi

     # check if user can read at least one docker config file, use sudo if user cannot read them
    if [ -f "$DOCKER_CONFIG" ]; then 
        if [[ ! -r "$DOCKER_CONFIG" ]]; then 
            SUDO="sudo"
            SUDO_E="sudo -E"
        fi
        return 0
    elif [ -f "$DOCKER_DAEMON" ]; then
        if [[ ! -r "$DOCKER_DAEMON" ]]; then
            SUDO="sudo"
            SUDO_E="sudo -E"
        fi
        return 0
    elif [ -S "$DOCKER_SOCKET" ]; then
        if [[ ! -r "$DOCKER_SOCKET" ]]; then
            SUDO="sudo"
            SUDO_E="sudo -E"
        fi
        return 0
    fi

    echo 'Missing administrator privileges. Please run with an account with sudo priviliges.'
    exit 1
}

require_sudo

# change working directory to directory of this script
pushd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" > /dev/null

ENV_FILE=".env"
# Get config file locations, first from env variable and fall back to .env file
if [ ! -f "$ENV_FILE" ]; then
    ENV_FILE="/opt/rita/.env"
fi

# Ensure that necessary config files exist
CONFIG_FILE="${CONFIG_FILE:-$($SUDO grep CONFIG_FILE "$ENV_FILE" | cut -d= -f2)}"
[ -f "$CONFIG_FILE" ] || { echo "RITA config file not found at '$CONFIG_FILE'"; exit 1; }

# Change back to original directory
popd > /dev/null

 
parse_flag() {
    case "$1" in
        # -l ./logs or --logs ./logs
        -l|--logs)
            LOGS="$2"
            RITA_ARGS+=("--logs=/tmp/zeek_logs");
            shift
            ;;
        # -l=./logs or --logs=./logs
        -l=*|--logs=*)
            LOGS="${1#*=}" # Extract the value after '='
            RITA_ARGS+=("--logs=/tmp/zeek_logs");
            ;;
        # any -flag= or --flag=
        -*=*|--*=*)
            RITA_ARGS+=("$1");
            ;;
        # any -flag <val> or --flag <val>
        -*|--*)
            RITA_ARGS+=("$1" "$2");
            shift
            
            ;;
        *)
        ;;
    esac   
}


COMPOSE_FILE="$(dirname "$ENV_FILE")/docker-compose.yml"

IS_HELP="false"

# For the most part, we can just pass all arguments directly through to rita.
# However, when the "import" command is run we need to mount the files or directories
# into the docker container. This handles that case by adding volume mounts
# to the DOCKER_ARGS.
while [[ $# -gt 0 ]]; do

	# Check if we're processing the "import" command. 
	if [ "$1" = "import" ]; then

        # check to see if rita is already running
        # RITA_RUNNING=$(docker compose -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "rita")
        if $SUDO docker compose -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "rita"; then
            echo "A RITA import is currently in progress... Wait for it to complete or stop the existing import."
            exit 1
        fi

		# Flag that we need to process the second to last argument.
		IS_IMPORT_COMMAND="true"

		# Pass the "import" argument through to rita.
		RITA_ARGS+=("$1"); shift

	# Process all flags after the import command.
	else
        case "$1" in
            *=*) # If the format is --key=value
                if [ -n "$1" ]; then
                  parse_flag "$1"
                fi
                ;;
            -*) # If the format is --key value
                # Check if next argument after hyphens is another flag 
                # (this means that this flag ($1) is a bool flag)
                if [ -n "$1" ]; then
                    if [[ "$2" == -* || -z "$2" ]]; then 
                        RITA_ARGS+=("$1");
                        if [[ "$1" == "--help" || "$1" == "-h" ]]; then
                            IS_HELP="true"
                        fi
                    else 
                        # Parse flag with value after it if it's not a bool flag
                        parse_flag "$1" "$2"
                        shift
                    fi
                fi
                ;;
            *)
            RITA_ARGS+=("$1")
            ;;    
        esac
    shift
    fi
done

if [[ "$IS_IMPORT_COMMAND" = true && "$IS_HELP" == false ]]; then 
    
    # check if logs flag was not passed
    if [ -z "$LOGS" ]; then
        echo "Path of logs to import was not supplied. Pass them in using --logs or -l"
        exit 1
    fi

    DIRECTORY="$LOGS"
    # Get the absolute path.
    ABS_PATH=$(realpath "$DIRECTORY")

    # Volume mount if the directory exists.
    if [ -d "$ABS_PATH" ]; then
        # Map to the same path inside the container for nicer status/error messages.
        DOCKER_ARGS+=("--volume" "$ABS_PATH:/tmp/zeek_logs")
        

    # If the argument is a file then mount in its parent directory. This wouldn't be
    # necessary but Zeek logs often have colons in their filenames (e.g. conn.00:00:00-01:00:00.log.gz)
    # and it's currently impossible to mount filenames with colons using
    # docker-compose --volume flags. Docker has the --mount flag that can handle this
    # but it has not been implemented in docker-compose.
    # https://github.com/moby/moby/issues/8604#issuecomment-332673783
    elif [ -f "$ABS_PATH" ]; then
        # Get the parent directory
        PARENT_PATH=$(dirname "$ABS_PATH")
        # Map to the same path inside the container for nicer status/error messages.
        # Duplicate entries are fine here.
        DOCKER_ARGS+=("--volume" "$PARENT_PATH:/tmp/zeek_logs")

    # If the file didn't exist then exit
    else
        echo "logs do not exist: $ABS_PATH"
        exit 1
    fi
fi

# Print out the final arguments and exit for debugging
#echo "DOCKER_ARGS: ${DOCKER_ARGS[@]}"; echo "RITA_ARGS: ${RITA_ARGS[@]}"; exit  # debug

# Change dir to install dir. The install dir is where the env file resides.
# Specifically wait to do this until after "realpath" is called so the user 
# can specify a relative path to their current working directory for their logs.
pushd "$(dirname "$ENV_FILE")" > /dev/null


# run RITA service
$SUDO docker compose -f ${COMPOSE_FILE} run ${DOCKER_ARGS[@]} rita "${RITA_ARGS[@]}"

# Store the exit code from docker-compose to use later
result=$?

# Change back to original directory
popd > /dev/null

# Pass docker-compose's exit code through
exit $result