import json
import argparse
import requests
import os
import csv


##### UPDATE DEFAULT VALUES AS NEEDED #############

def generate_scalar_value(name):
    return {
  "Boolean": True,
  "Float": 1.0,
  "ID": '123456789012',
  "Int": 1,
  "String": "123456",
  "Object": {'Key': 'pentest'},
  "DateTime": '11-11-1111',


    }.get(name, None)


####################################################





def init_csv(filepath):
    if not os.path.exists(filepath):
        with open(filepath, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["OperationType", "Field", "StatusCode", "Result", "Message", "Query", "Variables", "Response"])

def log_to_csv(op_type, field_name, status, result, message, query="", variables="", response="", filepath="results.csv"):
    with open(filepath, mode='a', newline='') as file:
        writer = csv.writer(file)
        # Convert complex objects to JSON strings for CSV storage
        variables_str = json.dumps(variables) if isinstance(variables, (dict, list)) else str(variables)
        response_str = json.dumps(response) if isinstance(response, (dict, list)) else str(response)
        writer.writerow([op_type, field_name, status, result, message, query, variables_str, response_str])


def parse_verbose_options(verbose_str):
    """Parse verbose options string like 'q,v,r' into a dict of booleans"""
    if not verbose_str:
        return {'query': False, 'variables': False, 'response': False}
    
    options = [opt.strip().lower() for opt in verbose_str.split(',')]
    return {
        'query': 'q' in options,
        'variables': 'v' in options, 
        'response': 'r' in options
    }

def color(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def green(text): return color(text, "92")
def red(text): return color(text, "91")
def yellow(text): return color(text, "93")
def blue(text): return color(text, "94")



def load_schema(schema_file):
    with open(schema_file, "r") as f:
        return json.load(f)["data"]["__schema"]

def build_type_map(schema):
    return {t["name"]: t for t in schema["types"]}

def unwrap_type(graphql_type):
    while graphql_type.get("kind") in ("NON_NULL", "LIST"):
        graphql_type = graphql_type["ofType"]
    return graphql_type

def generate_dummy_value(arg_type, type_map):
    kind = arg_type["kind"]
    name = arg_type.get("name")
    of_type = arg_type.get("ofType")

    if kind == "NON_NULL":
        return generate_dummy_value(of_type, type_map)
    elif kind == "LIST":
        return [generate_dummy_value(of_type, type_map)]
    elif kind == "SCALAR":
        return generate_scalar_value(name)
    elif kind == "ENUM":
        enum = type_map.get(name)
        if enum and enum.get("enumValues"):
            return enum["enumValues"][0]["name"]
        else:
            print(f"⚠️ No enum values found for {name}")
            return None
    elif kind == "INPUT_OBJECT":
        input_object = type_map.get(name)
        if not input_object or not input_object.get("inputFields"):
            return {}
        return {
            f["name"]: generate_dummy_value(f["type"], type_map)
            for f in input_object["inputFields"]
        }
    else:
        print(f"❓ Unknown kind: {kind}, name: {name}")
        return None


def build_selection_set(graphql_type, type_map, visited=None, depth=0, max_depth=20):
    """Build a comprehensive selection set for a GraphQL type"""
    if visited is None:
        visited = set()
    
    if depth > max_depth:
        return ""
    
    # Unwrap the type to get the base type
    base_type = unwrap_type(graphql_type)
    type_name = base_type.get("name")
    
    if not type_name or base_type["kind"] in ("SCALAR", "ENUM"):
        return ""
    
    # Prevent infinite recursion
    if type_name in visited:
        return ""
    
    visited.add(type_name)
    
    type_def = type_map.get(type_name)
    if not type_def or not type_def.get("fields"):
        visited.remove(type_name)
        return ""
    
    selections = []
    for field in type_def["fields"]:
        field_name = field["name"]
        field_type = field["type"]
        
        # Skip fields with required arguments for now
        if field.get("args") and any(arg["type"]["kind"] == "NON_NULL" for arg in field["args"]):
            continue
        
        nested_selection = build_selection_set(field_type, type_map, visited.copy(), depth + 1, max_depth)
        if nested_selection:
            selections.append(f"{field_name} {{{nested_selection}}}")
        else:
            selections.append(field_name)
    
    visited.remove(type_name)
    return " ".join(selections)

def is_scalar_or_enum(graphql_type, type_map):
    while graphql_type.get("kind") in ("NON_NULL", "LIST"):
        graphql_type = graphql_type["ofType"]
    return graphql_type["kind"] in ("SCALAR", "ENUM")


def build_minimal_selection_set(graphql_type, type_map):
    base_type = unwrap_type(graphql_type)
    type_name = base_type.get("name")
    if not type_name or base_type["kind"] in ("SCALAR", "ENUM"):
        return ""

    type_def = type_map.get(type_name)
    if not type_def or not type_def.get("fields"):
        return ""

    # preferred scalar field names
    preferred = ["message", "status", "data", "id", "name", "title"]
    for pref in preferred:
        for f in type_def["fields"]:
            if f["name"] == pref and is_scalar_or_enum(f["type"], type_map):
                return f["name"]

    # fallback: first scalar/enum field
    for f in type_def["fields"]:
        if is_scalar_or_enum(f["type"], type_map):
            return f["name"]

    return "__typename"


def build_query_string(field, type_map, op_type="query", full_output=False):
    args = field.get("args", [])
    arg_defs = []
    arg_values = []
    variables = {}

    for arg in args:
        # only include NON_NULL args in generated tests (same as original behavior)
        if arg["type"]["kind"] != "NON_NULL":
            continue

        dummy_value = generate_dummy_value(arg["type"], type_map)
        if dummy_value is not None:
            var_name = f"${arg['name']}"
            arg_defs.append(f"{var_name}: {get_graphql_type_string(arg['type'])}")
            arg_values.append(f"{arg['name']}: {var_name}")
            variables[arg["name"]] = dummy_value

    arg_defs_str = f"({', '.join(arg_defs)})" if arg_defs else ""
    arg_values_str = f"({', '.join(arg_values)})" if arg_values else ""

    return_type = field["type"]

    if is_scalar_or_enum(return_type, type_map):
        selection = ""
    else:
        if full_output:
            comprehensive_selection = build_selection_set(return_type, type_map)
        else:
            comprehensive_selection = build_minimal_selection_set(return_type, type_map)

        selection = f" {{ {comprehensive_selection} }}" if comprehensive_selection else " { __typename }"

    query_body = f"{field['name']}{arg_values_str}{selection}"
    query_string = f"{op_type} {arg_defs_str} {{ {query_body} }}"
    return query_string, variables



def get_graphql_type_string(arg_type):
    kind = arg_type["kind"]
    name = arg_type.get("name")
    of_type = arg_type.get("ofType")

    if kind == "NON_NULL":
        return f"{get_graphql_type_string(of_type)}!"
    elif kind == "LIST":
        return f"[{get_graphql_type_string(of_type)}]"
    else:
        return name

def run_graphql(endpoint, auth_token, query, variables):
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json"
    }
    response = requests.post(endpoint, headers=headers, json={
        "query": query,
        "variables": variables
    })
    return response.status_code, response.json()

def perform_introspection(endpoint, auth_token, output_file=None):
    """Perform GraphQL introspection query and save schema to JSON file"""
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    
    print(f"{blue('🔍 Performing GraphQL introspection...')}")
    
    try:
        status_code, response = run_graphql(endpoint, auth_token, introspection_query, {})
        
        if status_code == 200 and "errors" not in response and "data" in response:
            print(green("✅ Introspection successful!"))
            
            # Generate output filename if not provided
            if not output_file:
                output_file = "schema_introspection.json"
            
            # Save the schema to file
            with open(output_file, 'w') as f:
                json.dump(response, f, indent=2)
            
            print(f"{blue(f'📁 Schema saved to: {output_file}')}")
            
            # Print some basic stats about the schema
            schema = response["data"]["__schema"]
            types_count = len([t for t in schema["types"] if not t["name"].startswith("__")])
            query_fields = len(schema.get("queryType", {}).get("name", "")) if schema.get("queryType") else 0
            mutation_fields = len(schema.get("mutationType", {}).get("name", "")) if schema.get("mutationType") else 0
            subscription_fields = len(schema.get("subscriptionType", {}).get("name", "")) if schema.get("subscriptionType") else 0
            
            print(f"{blue('📊 Schema statistics:')}")
            print(f"  - Custom types: {types_count}")
            print(f"  - Has queries: {'Yes -> '+ str(query_fields) + ' queries' if schema.get('queryType') else 'No'}")
            print(f"  - Has mutations: {'Yes -> '+ str(mutation_fields) + ' mutations' if schema.get('mutationType') else 'No'}")
            print(f"  - Has subscriptions: {'Yes -> '+ str(subscription_fields) + ' subscriptions' if schema.get('subscriptionType') else 'No'}")
            
            return True, output_file
            
        else:
            print(red(f"❌ Introspection failed with status {status_code}"))
            if "errors" in response:
                for error in response["errors"]:
                    print(red(f"  ↳ Error: {error.get('message', 'Unknown error')}"))
            return False, None
            
    except Exception as e:
        print(red(f"❌ Exception during introspection: {e}"))
        return False, None


def list_scalars_mode(schema_file):
    schema = load_schema(schema_file)
    scalar_defaults = {
        "String": "123456",
        "ID": "123456789012",
        "Int": 1,
        "Float": 1.0,
        "Boolean": False,
        "Object": {"Key":"pentest"},
        "DateTime": '11-11-1111'
    }

    print(f"\nScalars found in schema '{schema_file}':\n")
    for t in schema["types"]:
        if t["kind"] == "SCALAR":
            if t["name"] in scalar_defaults:
                val = scalar_defaults[t["name"]]
            else:
                val = f"default_{t['name'].lower()}"
            print(f"  \"{t['name']}\": {repr(val)},")
    print("\nCopy the above lines into your generate_scalar_value dictionary as needed.\n")




def test_operations(schema, auth_token, endpoint, op_type="query", verbose_options=None, full_output=False, query_name=None, output='result.csv'):
    if verbose_options is None:
        verbose_options = {'query': False, 'variables': False, 'response': False}

    key = "queryType" if op_type == "query" else "mutationType"
    if not schema.get(key):
        print(yellow(f"[!] Schema has no {op_type} type; skipping."))
        return

    type_name = schema[key]["name"]
    type_map = build_type_map(schema)
    # find the typeDef for query/mutation root and get fields
    root_type_defs = [t for t in schema["types"] if t["name"] == type_name]
    if not root_type_defs:
        print(yellow(f"[!] Could not find root type '{type_name}' in schema."))
        return
    ops = root_type_defs[0].get("fields", [])

    # Filter by query_name if specified
    if query_name:
        ops = [op for op in ops if op["name"] == query_name]
        if not ops:
            print(yellow(f"[!] No {op_type} named '{query_name}' found in schema."))
            return

    print(f"\n=== Testing {op_type.title()}s (full_output={full_output}) ===")
    for field in ops:
        query = None
        variables = None
        try:
            query, variables = build_query_string(field, type_map, op_type, full_output)
            status, response = run_graphql(endpoint, auth_token, query, variables)

            # default (minimal) printing: just status line (still keep details on failure)
            if status == 200 and response and "errors" not in response:
                print(green(f"[{status}] {op_type} `{field['name']}` -> ✅ OK"))
                message = "Success"
            else:
                print(red(f"[{status}] {op_type} `{field['name']}` -> ❌ FAIL"))
                message = response.get('errors', [{}])[0].get('message', 'Unknown error') if response else 'No response'
                # print a short error summary
                print(yellow(f"  ↳ Error: {message}"))

            # Always log to CSV with full info
            result = "OK" if (status == 200 and response and "errors" not in response) else "FAIL"
            log_to_csv(op_type, field['name'], status, result, message, query, variables, response, filepath=output)

            # Print a business-level message if present -> needs to be adapted in function of context
            if response and ('data' in response) and ('errors' not in response):
                data = response['data'].get(field['name'])
                if isinstance(data, dict) and 'message' in data:
                    print(blue(f"  ↳ Message: {data['message']}"))


            # Verbose blabla
            if verbose_options.get('query'):
                print(f"\n{blue('=== Query ===')}")
                print(query)

            if verbose_options.get('variables'):
                print(f"\n{blue('=== Variables ===')}")
                print(json.dumps(variables, indent=2))

            if verbose_options.get('response') and response:
                print(f"\n{blue('=== Full Response ===')}")
                print(json.dumps(response, indent=2))

            

        except Exception as e:
            # avoid raising another exception while handling one
            q_for_log = query if 'query' in locals() and query is not None else ""
            v_for_log = variables if 'variables' in locals() and variables is not None else ""
            print(red(f"❌ Exception testing `{field['name']}`: {e}"))
            log_to_csv(op_type, field['name'], "N/A", "EXCEPTION", str(e), q_for_log, v_for_log, "", filepath=output)

def main(schema_file, auth_header, endpoint, verbose_str=None, introspection_mode=False, output=None, list_scalars=False, full_output=False, query_name=None):
    # Introspection mode - generate schema JSON from GraphQL endpoint
    if introspection_mode:
        success, output_file = perform_introspection(endpoint, auth_header, output)
        if success:
            print(f"{green('✅ Introspection completed successfully!')}")
            print(f"Use the generated file for testing: python {os.path.basename(__file__)} -s {output_file} -ah \"\" -u {endpoint}")
        return
    
    # Listing scalar mode - discover all scalar that needs default values
    if list_scalars:
        list_scalars_mode(args.schema)
        return
    
    # Normal testing mode
    init_csv(output)
    schema = load_schema(schema_file)
    verbose_options = parse_verbose_options(verbose_str)
    test_operations(schema, auth_header, endpoint, op_type="query", verbose_options=verbose_options, full_output=full_output, query_name=query_name, output=output)
    test_operations(schema, auth_header, endpoint, op_type="mutation", verbose_options=verbose_options, full_output=full_output, query_name=query_name, output=output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraphQL Auth Tester")
    group = parser.add_mutually_exclusive_group(required=True)

    # for testing
    group.add_argument("--schema", '-s', help="Path to GraphQL schema JSON file")
    parser.add_argument("--auth_header", "-ah", help="Authorization header, e.g., 'Bearer abc123'")
    parser.add_argument("--url", "-u", help="GraphQL endpoint URL ")
    parser.add_argument("--verbose", "-v", 
                        help="Print detailed output. Options: q (query), v (variables), r (response). Example: -v q,v,r or -v q,r")
    parser.add_argument("--list-scalars", "-ls", action="store_true",
                   help="List all scalar types from schema with suggested dummy values")
    parser.add_argument("--full-output", "-fo", action="store_true", help="Request full selection sets (default: minimal).")
    parser.add_argument("--query", "-q", help="Only run a specific query/mutation by name")

    #For introspection
    group.add_argument("--introspect", "-i", action="store_true", 
                       help="Generate schema JSON file from GraphQL introspection")
    
    parser.add_argument("--output", "-o", 
                        help="Output filename for json schema in introspection mode and csv in testing mode")
    
    args = parser.parse_args()

    output = args.output
    if not output and args.schema:
        output = "results.csv"
    
    if args.schema and args.list_scalars and args.url:
        print(red("Choose between listing scalar (-ls) and testing endpoint (-u)"))
        exit(1)
    
    if args.schema and not args.list_scalars and not args.url:
        print(red("Missing endpoint (-u) to test"))
        exit(1)
    

    main(args.schema, args.auth_header, args.url, args.verbose, 
         args.introspect, output,args.list_scalars,args.full_output, args.query)