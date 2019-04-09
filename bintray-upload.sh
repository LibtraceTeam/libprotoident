#!/bin/bash

set -e -o pipefail

BINTRAY_REPO="wand/libprotoident"
BINTRAY_LICENSE="LGPL-3.0"

apt-get update && apt-get install -y curl

curl --silent -fL -XGET \
    "https://api.bintray.com/content/jfrog/jfrog-cli-go/\$latest/jfrog-cli-linux-amd64/jfrog?bt_package=jfrog-cli-linux-amd64" \
    > /usr/local/bin/jfrog
chmod +x /usr/local/bin/jfrog
mkdir ~/.jfrog/
cat << EOF > ~/.jfrog/jfrog-cli.conf
{
  "artifactory": null,
  "bintray": {
    "user": "${BINTRAY_USERNAME}",
    "key": "${BINTRAY_API_KEY}"
  },
  "Version": "1"
}
EOF

for path in `find built-packages/ -maxdepth 1 -type d`; do
    IFS=_ read linux_version <<< $(basename "${path}")
    for deb in `find "${path}" -maxdepth 1 -type f`; do
        pkg_filename=$(basename "${deb}")
        IFS=_ read pkg_name pkg_version pkg_arch <<< $(basename -s ".deb" "${pkg_filename}")
        jfrog bt package-create --licenses ${BINTRAY_LICENSE} --vcs-url ${CI_PROJECT_URL} ${BINTRAY_REPO}/${pkg_name} || true
        jfrog bt upload --deb ${linux_version}/main/${pkg_arch} ${deb} ${BINTRAY_REPO}/${pkg_name}/${pkg_version} pool/${linux_version}/main/${pkg_name}/
    done
done

