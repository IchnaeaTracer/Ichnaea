#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
from datetime import datetime
import struct
import json

# Layout files tell the decoder how to interpret the binary data
# This is a dummy layout file for ngx_module_t and int
# The layout for your traced objects  will depend on the actual structure of the objects you are tracing.
# Visit https://docs.python.org/3/library/struct.html for more info on python struct unpacking
# @ in the fmt means native byte ordering
# Here Q is used for unsigned long long (8 bytes)
# and P is used for pointer (8 bytes)
# layouts = {
#     "int" : {
#         "fmt" : "i",
#         "struct_layout" : [
#             "int int: "
#         ]
#     },
#     "ngx_module_t" : {
#         "fmt" : "@QQPQQQPPPQPPPPPPPQQQQQQQQ",
#         "struct_layout" : [
#             "ngx_uint_t  ctx_index",
#             "ngx_uint_t  index",
#             "char  *name",
#             "ngx_uint_t  spare0",
#             "ngx_uint_t  spare1",
#             "ngx_uint_t  version",
#             "const char *signature",
#             "void  *ctx",
#             "ngx_command_t   *commands",
#             "ngx_uint_t  type",
#             "ngx_int_t (*init_master)(ngx_log_t *log)",
#             "ngx_int_t (*init_module)(ngx_cycle_t *cycle)",
#             "ngx_int_t (*init_process)(ngx_cycle_t *cycle)",
#             "ngx_int_t (*init_thread)(ngx_cycle_t *cycle)",
#             "void (*exit_thread)(ngx_cycle_t *cycle)",
#             "void (*exit_process)(ngx_cycle_t *cycle)",
#             "void (*exit_master)(ngx_cycle_t *cycle)",
#             "uintptr_t   spare_hook0",
#             "uintptr_t   spare_hook1",
#             "uintptr_t   spare_hook2",
#             "uintptr_t   spare_hook3",
#             "uintptr_t   spare_hook4",
#             "uintptr_t   spare_hook5",
#             "uintptr_t   spare_hook6",
#             "uintptr_t   spare_hook7"
#         ]
#     }
# }

#  Write a dummy layouts dict to a json file and retireve it
# with open("layouts.json", "w") as f:
#     json.dump(layouts, f, indent=4)



# Global variable to hold layouts
layouts = {}
discovered_session_files = {} # "session_id" : "path/to/session_file.csv"
discovered_objects = {}  # "session_id" : {"object_name1" : {}, "object_name_2" : {}, ...}

# Updates the discover_session_files dictionary with session IDs and their corresponding file paths
def discover_sessions(directory):
    sessions = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.startswith('map@') and file.endswith('.csv'):
                session_id = file.split('session:')[1].split(']')[0]
                session_path = os.path.join(root, file)
                if session_id not in discovered_session_files:
                    discovered_session_files[session_id] = session_path

def session_id_to_datetime(session_id):
    """
    Convert session ID to a datetime object.
    """
    # Assuming session_id is a timestamp in seconds
    from datetime import datetime
    k = datetime.fromtimestamp(int(session_id))
    return k.strftime("%Y-%m-%d %H:%M:%S")

def check_addr(addr, mapfile):
    if addr == "0x0" or addr == "0":
        return "Null"
    try:
        with open(mapfile, "r", encoding="utf-8") as f:
            for line in f:
                if "start_addr" in line:
                    continue
                if len(line.strip()) < 5:
                    continue
                try:
                    start_addr, end_addr, function_name = line.strip().split(",")
                except:
                    continue
                if int(start_addr, 16) <= int(addr, 16) <= int(end_addr, 16):
                    # Calculate the offset from the start address
                    offset = int(addr, 16) - int(start_addr, 16)
                    # Return the function name with offset
                    return function_name.strip() + f" + {offset:#x}" if offset != 0 else "{}"
    except Exception as e:
        return f"Error: {e}"
    return "Unknown"

def decode_snapshot(snapshot_file, type , map_csv , snap_id = None ,):
    snapshot_file = os.path.abspath(snapshot_file)

    is_v2 = True if snapshot_file.endswith(".bin") else False

    if type in layouts:
        fmt = layouts[type]["fmt"]
        struct_layout = layouts[type]["struct_layout"]
    else:
        print(f"Error: Layout for type '{type}' not found in layouts.json.")
        return
    
    if is_v2 and snap_id is None:
        print("Error: For v2 snapshots, you must provide a snap_id.")
        return
    
    output = {}

    try:
        with open(snapshot_file, "rb") as f:
            data = f.read()
            if is_v2:
                size_of_one_snap = snapshot_file.split("size:")[1].split("]")[0]
                data = data[int(snap_id) * int(size_of_one_snap): (int(snap_id) + 1) * int(size_of_one_snap)]
            
            if fmt == 's': # It's a char buffer
                # Get the size of the object from file name
                size_of_object = snapshot_file.split("size:")[1].split("]")[0]
                if size_of_object.isdigit():
                    size_of_object = int(size_of_object)
                else:
                    size_of_object = 0
                unpacked = list(struct.iter_unpack(f"{size_of_object}{fmt}", data))[0]
            else:
                unpacked = list(struct.iter_unpack(fmt, data))[0]

            

            for idx, item in enumerate(unpacked):
                if fmt[idx] == "s":  # If it's a string
                    # If it's a string, decode it
                    item = item.decode('ascii', errors='ignore')

                value = hex(item) if fmt[idx] == "P" else item
                extra = check_addr(value, map_csv) if fmt[idx] == "P" else ""
                output[f"{struct_layout[idx]}"] =  value if not extra else [value , {"resolved_fn_name:": extra}]
    except Exception as e:
        print("Failed to decode binary snapshot:", e)
    
    return output

def discover_objects(directory, session_id):
    global discovered_objects
    if session_id not in discovered_objects:
        discovered_objects[session_id] = {}
    
    files = os.listdir(directory)
    for file_ in files:
        # Filter out other sesson files
        if f"session:{session_id}" in file_:
            # Discover cg and .json files
            if file_.endswith('.cg'):
                object_name = file_.split('name:')[1].split(']')[0]
                object_path = os.path.join(directory, file_)
                object_size = file_.split('size:')[1].split(']')[0]
                snap_number = file_.split('snap:')[1].split(']')[0]
                pid = 0
                tid = 0
                type = ""
                call_graphs = []

                
                # Read the file and filsh out pid and tid
                with open(object_path, 'r') as f:
                    lines = f.readlines()
                    if len(lines) > 0:
                        first_line = lines[0].strip()
                        # Line looks like this: PID: 930765, TID: 930765
                        pid = int( first_line.split(',')[0].split(':')[1].strip())
                        tid = int( first_line.split(',')[1].split(':')[1].strip())

                        second_line = lines[1].strip()
                        type = second_line.split('type:')[1].strip()

                        # Call graphs are in the rest of the file
                        for line in lines[2:]:
                            call_graphs.append(line.strip())
                
                decoded_data = decode_snapshot(
                    object_path[:-3],
                    type,
                    discovered_session_files[session_id],
                )



                if object_name not in discovered_objects[session_id]:
                    k = {
                        object_name: {
                            "type": type,
                            "size": object_size,
                            "total_snapshots": 1,
                            "snapshots": {
                                snap_number: {
                                    "data" : decoded_data,
                                    "callstack": call_graphs,
                                    "pid": pid,
                                    "tid": tid,
                                    "timestamp":  session_id_to_datetime(session_id),
                                    "path": object_path[:-3]
                            }

                        }
                    }
                    }
    
                    discovered_objects[session_id][object_name] = k[object_name]
                    print(f"Discovered object: {object_name} in session {session_id}")
                else:
                    # If the object already exists, just update the snapshots
                    discovered_objects[session_id][object_name]["snapshots"][snap_number] = {
                        "data" : decoded_data,
                        "callstack": call_graphs,
                        "pid": pid,
                        "tid": tid,
                        "timestamp": session_id_to_datetime(session_id),
                        "path": object_path
                    }
                    discovered_objects[session_id][object_name]["total_snapshots"] += 1
                    print(f"Updated object: {object_name} in session {session_id}")
            elif file_.endswith('.json'):
                # If it's a json file then one snapshot file contains data for multiple snapshots
                object_name = file_.split('name:')[1].split(']')[0]
                object_path = os.path.join(directory, file_)

                json_data = {}
                # Read the json file to get the type and size
                with open(object_path, 'r') as f:
                    json_data = json.load(f)
                
                # Remove the "obj" prefix and ".json" suffix
                snapshot_file = "snap" + file_[3:-5] + ".bin"
                snapshot_file = os.path.join(directory, snapshot_file)

                k = {
                    object_name: {
                        "type": json_data['object']["type"],
                        "size": json_data['object']["size"],
                        "total_snapshots": json_data['object']["snap_count"],
                        "snapshots": {}
                    }
                }

                discovered_objects[session_id][object_name] = k[object_name]
                _seen_hashes = set()  # To keep track of already seen snapshot hashes
                for snap_id in range( 0, json_data['object']["snap_count"]):
                    decoded_data = decode_snapshot(
                        snapshot_file,
                        json_data['object']["type"],
                        discovered_session_files[session_id],
                        snap_id
                    )

                    # Hash the edecoded data
                    _hash = hash( json.dumps(decoded_data , sort_keys=True) )
                    _seen_hashes.add(_hash)

                    if decoded_data is None:
                        print(f"Failed to decode snapshot {snap_id} for object {object_name} in session {session_id}")
                        continue

                    if json_data[f'snapshot_{snap_id}']["is_syscall_dump"] == True:
                        if _hash in _seen_hashes:
                            print(f"Skipping snapshot {snap_id} for object {object_name} in session {session_id} due to duplicate hash.")
                            continue
                    # Add the snapshot data to the discovered_objects dictionary
                    _tmp_cs_stk = []
                    for i in json_data[f'snapshot_{snap_id}']["call_stack"]:
                        fn__ = check_addr(i, discovered_session_files[session_id])
                        if fn__ != "Unknown":
                            _tmp_cs_stk.append( [i, {"resolved_fn_name" : fn__ }] )

                    k[object_name]["snapshots"][str(snap_id)] = {
                        "data": decoded_data,
                        "callstack": _tmp_cs_stk,
                        "pid": json_data[f'snapshot_{snap_id}']["pid"],
                        "tid": json_data[f'snapshot_{snap_id}']["tid"],
                        "is_syscall_dump": json_data[f'snapshot_{snap_id}']["is_syscall_dump"],
                        "timestamp": session_id_to_datetime(session_id),
                        "path": snapshot_file,
                        "hash": _hash
                    }




    # Oranize the "snapshots" dictionary to be sorted by snapshot number
    for object_name, object_data in discovered_objects[session_id].items():
        sorted_snapshots = dict(sorted(object_data["snapshots"].items(), key=lambda item: int(item[0])))
        discovered_objects[session_id][object_name]["snapshots"] = sorted_snapshots
    
    # Write the discovered objects to a JSON file
    with open(f"discovered_objects_{session_id}.json", "w") as f:
        json.dump(discovered_objects, f, indent=4)

# Return the chose thing (not the index) from the list of things
def let_user_choose(list_of_things, name_of_thing):
    global discovered_objects
    print(f"Please choose a {name_of_thing} from the list below:")
    for i, item in enumerate(list_of_things):
        print(f"{i + 1}. {item}")
    
    while True:
        try:
            choice = int(input(f"Enter the number corresponding to your choice (1-{len(list_of_things)}): "))
            if 1 <= choice <= len(list_of_things):
                return list_of_things[choice - 1]
            else:
                print(f"Invalid choice. Please enter a number between 1 and {len(list_of_things)}.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


def main():
    global layouts

    tmp_dir = ""

    # Check for command line arguments
    if len(sys.argv) < 2:
        print("Usage: python decode2.py <trace_directory> <optional: dump_all_sessions(-d)>")
        if not os.path.exists(tmp_dir):
            sys.exit(1)
        trace_directory = tmp_dir
    else:
        trace_directory = sys.argv[1]
    
    dump_all_sessions = False
    if len(sys.argv) >= 3 and (sys.argv[2].lower() == "-dump_all_sessions" or sys.argv[2].lower() == "-d"):
        dump_all_sessions = True

    # Check if the provided path is a directory
    if not os.path.isdir(trace_directory):
        print(f"Error: {trace_directory} is not a valid directory.")
        sys.exit(1)
    
    # Check if the trace directory contains any files
    if not os.listdir(trace_directory):
        print(f"Error: {trace_directory} is empty.")
        sys.exit(1)
    
    # Check if the layouts file exists
    if os.path.exists("layouts.json"): # Searching for layouts.json in the current directory
        with open("layouts.json", "r") as f:
            layouts = json.load(f)
    else:
        # Try looking in the trace directory
        if os.path.exists(os.path.join(trace_directory, "layouts.json")):
            with open(os.path.join(trace_directory, "layouts.json"), "r") as f:
                layouts = json.load(f)
        else:
            print("Error: layouts.json file not found in the current directory or trace directory.")
            sys.exit(1)
    
    # Discover session files
    discover_sessions(trace_directory)

    if not discovered_session_files:
        print("No session files found in the specified directory.")
        sys.exit(1)
    
    if dump_all_sessions:
        print("Dumping all discovered sessions:")
        for session_id in discovered_session_files.keys():
            discover_objects(trace_directory, session_id)
        print("All sessions dumped successfully.")
        return

    # Let the user choose a session file
    chosen_session = let_user_choose(list(discovered_session_files.keys()), "session ID")

    print(f"You chose session ID: {chosen_session}")

    # Discover objects in the chosen session
    discover_objects(trace_directory, chosen_session)
    print(f"Discovered objects for session {chosen_session}:")


if __name__ == "__main__":
    main()
    print("Done.")
    sys.exit(0)

