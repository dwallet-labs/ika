#!/bin/bash

# Fast fail on errors or unset variables
set -e

DIR="$( cd "$( dirname "$0" )" && pwd )"
REPO_ROOT="$(git rev-parse --show-toplevel)"
DOCKERFILE="$DIR/Dockerfile"
GIT_REVISION="$(git describe --always --abbrev=12 --dirty --exclude '*')"
BUILD_DATE="$(date -u +'%Y-%m-%d')"

# Load environment variables from .env if not already set
if [ -f .env ]; then
  echo "Loading variables from .env"
  while IFS='=' read -r key value; do
    # Skip comments and empty lines
    if [ -z "$key" ] || echo "$key" | grep -q '^#'; then
      continue
    fi

    # Only export if not already set in environment
    if [ -z "${!key}" ]; then
      export "$key=$value"
    fi
  done < .env
fi

# Validate required variables
: "${GH_DEPLOY_KEY:?GH_DEPLOY_KEY is not set. Check your .env or environment.}"
: "${DOCKER_TAG:?DOCKER_TAG is not set. Check your .env or environment.}"

# Handle optional flags
PROFILE="release"

while [[ $# -gt 0 ]]; do
  case $1 in
    --debug-symbols)
      PROFILE="bench"
      echo "Building with full debug info enabled ... WARNING: binary size might significantly increase"
      shift
      ;;
    *)
      break
      ;;
  esac
done

echo
echo "Building ika-proxy docker image"
echo "Dockerfile:      $DOCKERFILE"
echo "Docker context:  $REPO_ROOT"
echo "Build date:      $BUILD_DATE"
echo "Git revision:    $GIT_REVISION"
echo "Docker tag:      $DOCKER_TAG"
echo "Build profile:   $PROFILE"
echo

docker build -f "$DOCKERFILE" "$REPO_ROOT" \
  --build-arg GIT_REVISION="$GIT_REVISION" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --build-arg PROFILE="$PROFILE" \
  --build-arg GH_DEPLOY_KEY="GH_DEPLOY_KEY" \
  --tag "$DOCKER_TAG" \
  "$@"
