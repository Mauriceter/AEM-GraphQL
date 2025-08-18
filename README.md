# AEM-GraphQL

**AEM-GraphQL** (Authorization endpoint mapper for GraphQL) is a security testing tool designed to help penetration testers assess authorization controls in GraphQL APIs. It automatically generates and executes default queries and mutations for every discovered endpoint, enabling **rapid mapping and validation of access permissions**. Results are saved in a csv file. This tool can also be used to test payloads, an SQLi for example on strings input of all the queries and mutations at once.

# Options

```
└─$ python3  AEM-GraphQL.py -h   
usage: AEM-GraphQL.py [-h] [--schema SCHEMA] [--auth_header AUTH_HEADER] [--url URL] [--verbose VERBOSE]
                      [--list-scalars] [--full-output] [--query QUERY] [--introspect] [--output OUTPUT]

GraphQL Auth Tester

options:
  -h, --help            show this help message and exit
  --schema, -s SCHEMA   Path to GraphQL schema JSON file
  --auth_header, -ah AUTH_HEADER
                        Authorization header, e.g., 'Bearer abc123'
  --url, -u URL         GraphQL endpoint URL
  --verbose, -v VERBOSE
                        Print detailed output. Options: q (query), v (variables), r (response). Example: -v q,v,r
                        or -v q,r
  --list-scalars, -ls   List all scalar types from schema with suggested dummy values
  --full-output, -fo    Request full selection sets (default: minimal).
  --query, -q QUERY     Only run a specific query/mutation by name
  --introspect, -i      Generate schema JSON file from GraphQL introspection
  --output, -o OUTPUT   Output filename for json schema in introspection mode and csv in testing mode
```


# How to use

1. **Extract the schema from GraphQL**
> ⚠️ **Warning:** This requires GraphQL introspection to be enabled in order to work.

```
└─$ python3 AEM-GraphQL.py -i -u https://endpoint.com/graphql -o schema.json  
🔍 Performing GraphQL introspection...
✅ Introspection successful!
📁 Schema saved to: schema.json
📊 Schema statistics:
  - Custom types: 173
  - Has queries: Yes -> 5 queries
  - Has mutations: Yes -> 8 mutations
  - Has subscriptions: No
✅ Introspection completed successfully!
Use the generated file for testing: python AEM-GraphQL.py -s schema.json -ah "" -u https://endpoint.com/graphql

```

2. **Generate dummy values for all scalars**

```
└─$ python3 AEM-GraphQL.py -s schema.json -ls                        

Scalars found in schema 'schema.json':

  "Boolean": False,
  "ID": '123456789012',
  "String": '123456',
  "Float": 1.0,
  "Object": {'Key': 'pentest'},
  "Int": 1,

Copy the above lines into your generate_scalar_value dictionary as needed.
```

This lists all scalars used by the GraphQL api, you can then choose your default values and update generate_scalar_value at the top of the script.

```
##### UPDATE DEFAULT VALUES AS NEEDED #############

def generate_scalar_value(name):
    return {
  "Boolean": True,
  "Float": 1.0,
  "ID": '123456789012',
  "Int": 1,
  "String": "abcdef",
  "Object": {'Key': 'pentest'},

    }.get(name, None)


####################################################
```

3. **Test all queries and mutations**

```
└─$ python3 AEM-GraphQL.py -s schema.json -u https://endpoint.com/graphql -ah "Bearer blabla" -o authorization_result.csv

=== Testing Queries (full_output=False) ===
[200] query `getUser` -> ❌ FAIL
  ↳ Error: Second Factor is not yet authenticated
[200] query `getUsers` -> ❌ FAIL
  ↳ Error: Second Factor is not yet authenticated
[200] query `getProfile` -> ✅ OK
[200] query `getPasswordHistory` -> ✅ OK

...

```

# Additional, yet important notes:

* Use **-q "getUsers"** to only test one query or mutations. Add **-c** to get the curl request instead.
* **⚠️ Authorization discovered are not perfect**, use **-v r** to print the full response or check the csv file.
* Generated queries and mutations use only required parameters to reduce the risque of errors in the query. This mean that if you use the tool to test a payload like an SLQi on all queries and mutations some parameters won't be tested
* Generated queries and mutations return by default only one scalar to reduce the risk of errors. Use **-fo** to return the full selection (some debugging still needed for deeply nested selections and when several types can be returned)


# TODO

* Add Subscription queries
* Correct number of query and mutation
* Better handling of --full-output
* Add option to test all parameters
* Adding parameter to indicate this error means a success and vice versa
