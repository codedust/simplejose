# SPDX-FileCopyrightText: 2021 2021 Marco Holz <code-iethi9Lu@marcoholz.de>
#
# SPDX-License-Identifier: CC0-1.0

if [[ -z "$1" || -z "$2" ]]; then
  echo "Usage: $0 schema.json validate-schema.js"
  echo ""
  echo "This will compile schema.json to a Javascript module that validates the schema"
  echo "see https://github.com/ajv-validator/ajv-cli#compile-schemas"
  exit
fi

echo 'let module = {};' > $2
./node_modules/.bin/ajv compile -s $1 -o >> $2
replace 'const func0 = require("ajv/dist/runtime/equal").default;' '' -- $2
echo 'export default validate20;' >> $2
reuse addheader --copyright='2016-2020 Jesse Collis, Evgeny Poberezkin' --license='MIT' $2 
