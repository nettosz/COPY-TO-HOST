# COPY TO HOST

COPY TO HOST is a Python-based application designed to facilitate the copying of folders to multiple hosts within a specified IP range. The application also supports creating shortcuts on remote machines and executing scripts remotely. The user interface is built using PySimpleGUI.

## Features

- Copy folders to multiple hosts within a specified IP range.
- Create shortcuts on remote machines.
- Execute scripts remotely on multiple hosts.
- Monitor network usage.
- Log activities and display them in the GUI.
- Load IP addresses from a file.

## Requirements

- Python 3.x
- PySimpleGUI
- pythonping
- psutil
- pywin32
- PSTools (for remote script execution)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/copy-to-host.git
    cd copy-to-host
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

3. Download and extract PSTools to the project directory:
    - [PSTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)

## Usage

1. Run the application:
    ```sh
    python file-sharev2.py
    ```

2. The GUI will open with the following tabs:
    - **LOGS GERAL**: Displays general logs.
    - **LISTA IPS**: Displays the list of IPs.

3. The main functionalities are divided into three tabs:
    - **TAB 1**: Copy folders to hosts.
        - Select the folder to be copied.
        - Specify the IP range (start and end IP).
        - Choose whether to replace existing folders and/or create shortcuts.
        - Click "Iniciar" to start the process.
        - Click "Stop" to stop all running threads.
        - Click "Pegar do aquivo" to load IPs from 

ips.txt

.
        - Click "Limpar" to clear the IP list.

    - **TAB 2**: Create shortcuts on remote machines.
        - Specify the path of the shortcut.
        - Optionally, provide a name for the shortcut.
        - Click "Criar" to create the shortcut.

    - **TAB 3**: Execute scripts remotely.
        - Specify the script path and a keyword filter.
        - Provide the output file name.
        - Click "Executar" to execute the script on the specified IP range.

## Functions

- 

stop_all(list_threads)

: Stops all running threads.
- 

update_ips(ip, ips, err)

: Updates the IP list with the status of each IP.
- 

parse_filter(filter, sub)

: Parses the filter string and replaces placeholders.
- 

get_network_usage()

: Monitors and updates network usage.
- 

set_current(ip)

: Sets the current IP being processed.
- 

read_bat_as_string(file_path)

: Reads a .bat file as a string.
- 

append_to_file(file_path, string_to_append)

: Appends a string to a file.
- 

execute_bat_remotely(remote_machine, bat_script_path)

: Executes a .bat script remotely.
- 

create_shortcut(target_path, shortcut_path, ip, ips, arguments, working_directory, icon_path, icon_index)

: Creates a shortcut on a remote machine.
- 

criar_atalhos(start_ip, end_ip, path, atl_name)

: Creates shortcuts on multiple hosts.
- 

get_username_by_ip(ip_address)

: Retrieves the username of a remote machine.
- 

save_list_to_file(file_path, my_list)

: Saves a list to a file.
- 

get_file(file)

: Reads IPs from a file.
- 

is_valid_ipv4_address(ip_address)

: Validates an IPv4 address.
- 

make_log(msg)

: Logs a message.
- 

get_range(start_ip, end_ip)

: Generates a range of IP addresses.
- 

is_reachable_worker(ip)

: Checks if an IP address is reachable.
- 

get_reachable_hosts(ips)

: Gets reachable hosts from a list of IPs.
- 

copy_folder_to_ips(folder_path, ips, sub)

: Copies a folder to multiple hosts.
- 

name_host(addr)

: Retrieves the hostname of an IP address.
- 

exec_script(ipi, ipf, script_path, outfile, filter)

: Executes a script on multiple hosts.
- 

start(folder_to_copy, start_ip, end_ip, ip_list, sub)

: Starts the folder copying process.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgements

- [PySimpleGUI](https://pysimplegui.readthedocs.io/)
- [pythonping](https://github.com/alessandromaggio/pythonping)
- [psutil](https://psutil.readthedocs.io/)
- [pywin32](https://github.com/mhammond/pywin32)
- [PSTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
