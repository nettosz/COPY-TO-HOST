import os
import shutil
import subprocess
from typing import List
import PySimpleGUI as sg
import threading
from pythonping import ping
import re
import os
import socket
import os
import win32com.client
import time
import psutil
from multiprocessing.pool import ThreadPool

logs = []
ip_list = []
hosts_online = []

file_name = "ips.txt"

#Threads rodando agora
running_threads = []

sg.theme("Dark Grey 13")   # Add a touch of color
# All the stuff inside your window.

layout = [
            
            [sg.Text('Atual: '),sg.Text("0.0.0.0", text_color='red', key="sts"), sg.Text("Rede: "), sg.Text("0.00 Mbps", key="sts_net")],
            
            [sg.TabGroup([[
            sg.Tab('LOGS GERAL',[
                [sg.Listbox([""], s=(35,10), key='_LISTBOX_', horizontal_scroll=True)],
            ]),
            sg.Tab("LISTA IPS", [
                [sg.Listbox([""], s=(35,10), key='_LISTBOX_IPS', horizontal_scroll=False)],
            ])
            ]])],

            [sg.TabGroup([[
            sg.Tab('TAB 1',[
            [sg.Text('Pasta a ser copiada:')],
            [sg.Input(s=15, key="folder", enable_events=True, visible=True), sg.FolderBrowse("Buscar Pasta", target="folder")],
            
            [sg.InputText(s=11, key="ipi"), sg.Text('-'), sg.InputText(s=11, key="ipf")],
            [sg.Checkbox("SUBSTITUIR", key="sub"), sg.Checkbox("CRIAR ATALHO", key="atl")], 
        
            [sg.Button("Iniciar", key="start"),sg.Button("Stop", key="stop_all"), sg.Button("Pegar do aquivo", key="getf"),
            sg.Button("Limpar", key="clear")],
            ]),

            sg.Tab('TAB 2',[
            
            [sg.Text('Caminho do atalho:')],
            [sg.Input(s=15, key="folder_at", visible=True)],
            [sg.Text('Nome do atalho (Opcional):')],
            [sg.Input(s=15, key="atl_name", visible=True)],
            [sg.Button("Criar", key="criar")],
            ]),
            sg.Tab('TAB 3',[

                [sg.Text('Caminho do Script:'), sg.Text('Key word:')],
                [sg.Input(s=15, key="script", visible=True), sg.Input(s=15, key="filter", visible=True)],
                [sg.Text('Arquivo de saida:')],
                [sg.Input(s=15, key="out_name", visible=True)],
                [sg.Button("Executar", key="exec")]

            ])
            ]])],

            [sg.Text('Powered by: TI - AMCEL')]
            ]

# Create the Window
window = sg.Window('COPY TO HOST', layout
)

def stop_all(list_threads):
    [thread.join() for thread in list_threads]

def update_ips(ip, ips, err):
    if err:
        ips[ips.index(ip)] = f"{ip} [ERRO]"
    else:
        ips[ips.index(ip)] = f"{ip} [OK]"
    
    window['_LISTBOX_IPS'].update([f"-> {ip}" for ip in ips])
    
    # for i in ips:
    #     if ip in i:
    #         if err:
    #             ips[ips.index(i)] = f"-> {i} [ERRO]"
    #         else:
    #             ips[ips.index(i)] = f"-> {i} [OK]"


# def load_ips(ips):
#     loaded_ips = [f"-> {i}" for i in ips]

#     window['_LISTBOX_IPS'].update(loaded_ips)

def parse_filter(filter:str, sub):
    nome = "@nome"

    if nome in filter:
        user_name = get_username_by_ip(sub)
        filter = filter.replace(nome, user_name)

    return filter

def get_network_usage():
    while True:
        # Get initial network stats
        initial_stats = psutil.net_io_counters()

        # Wait for a short interval
        time.sleep(1)

        # Get updated network stats
        updated_stats = psutil.net_io_counters()

        # Calculate bytes transferred during the interval
        bytes_sent = updated_stats.bytes_sent - initial_stats.bytes_sent
        #bytes_recv = updated_stats.bytes_recv - initial_stats.bytes_recv

        # Calculate network usage in bits per second (bps)
        network_usage_bps = (bytes_sent) * 8

        # Convert bps to Mbps
        network_usage_mbps = network_usage_bps / 1e6

        window["sts_net"].update(f"{network_usage_mbps:.2f} Mbps")

# Create a thread for updating network usage
network_thread = threading.Thread(target=get_network_usage)

# Start the thread
network_thread.daemon = True
running_threads.append(network_thread)
network_thread.start()

def set_current(ip):
    window["sts"].update(ip)

def read_bat_as_string(file_path):
    try:
        with open(file_path, 'r') as bat_file:
            bat_contents = bat_file.read().split("\n")
            if len(bat_contents) > 1:
                bat_contents = '&'.join(bat_contents)
                return bat_contents
                
        return bat_contents[0]
    except:
        make_log(f"-> Erro ao ler o arquivo .bat")
        
def append_to_file(file_path, string_to_append):
    with open(file_path, 'w') as file:
        file.write(string_to_append)
    
def execute_bat_remotely(remote_machine, bat_script_path):
    try:
        # Replace 'username' and 'password' with appropriate credentials if needed
        psexec_path = ".\PSTools\PsExec.exe"
        
        bat_content = read_bat_as_string(bat_script_path)

        psexec_command = f'{psexec_path} \\\\{remote_machine} -i -s cmd /c "{bat_content}"'

        result = subprocess.run(psexec_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        if result.returncode == 0:
            make_log(f"-> Script {bat_script_path} exec in >> {remote_machine}")
            return result.stdout
        else:
            make_log(f"-> Erro ao executar o script .bat remotamente em {remote_machine}.")
            return result.stdout
        
    except Exception as e:
        return make_log(f"-> Aconteceu um erro: {e}")
    
def create_shortcut(target_path, shortcut_path, ip, ips, arguments="", working_directory="", icon_path="", icon_index=0):
    #Error var
    err = ""
    
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = target_path
        shortcut.Arguments = arguments
        shortcut.WorkingDirectory = working_directory
        shortcut.IconLocation = icon_path + "," + str(icon_index)
        shortcut.save()
    except Exception as e:
        err = e
        make_log(f"-> Ocorreu um erro: {e}")

    update_ips(ip, ips, err=err)

def criar_atalhos(start_ip, end_ip, path, atl_name):
    ips = get_range(start_ip, end_ip)
    ip_addresses, non_reachable = get_reachable_hosts(ips)

    for ip in ip_addresses:
        #Seta o ip atual
        set_current(ip)

        name = get_username_by_ip(ip)
            
        if atl_name:
                file = atl_name
        else:
            file = path.split("\\")[-1]

        shortcut_path = f"\\\\{ip}\\c$\\Users\\{name}\\Desktop\\{file}.lnk"
        #target_path = f"\\\\{ip}\\c$\\{path}"
        target_path = f"c:\\{path}"
        
        create_shortcut(target_path, shortcut_path, ip, ip_addresses)
        make_log(f"-> Atalho criado: {target_path} ==> {shortcut_path}")

    make_log(f"-> Criar atalhos finalizado")

def get_username_by_ip(ip_address):
    try:
        # Use the `subprocess.check_output()` function to execute a Windows command to get the username
        command = f"wmic /node:{ip_address} computersystem get username /value"
        output = subprocess.check_output(command, shell=True, text=True)

        # Process the output to extract the username
        username = output.strip().split('=')[1].split("\\")[1]
        
        return username

    except (socket.herror, subprocess.CalledProcessError, IndexError) as e:
        make_log(f"-> Ocorreu um erro: {e}")
        return None
    
def save_list_to_file(file_path, my_list):
    # Convert the list elements to strings (if needed)
    str_list = [str(item) for item in my_list]

    # Join the list elements into a \n string
    csv_data = '\n'.join(str_list)
    
    # Open the file in write mode and save the data
    with open(file_path, 'w') as file:
        file.write(csv_data)

def get_file(file):
    with open(file, "r") as f:
        text = f.read()
        ips = text.split("\n")
    return ips

def is_valid_ipv4_address(ip_address):
    # Regular expression pattern for IPv4 address
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    # Match the pattern against the given IP address
    match = re.match(pattern, ip_address)
    
    # If match is found, it's a valid IPv4 address
    if match:
        return True
    else:
        return False

def make_log(msg):
    global logs
    logs.append(msg)
    window.Element('_LISTBOX_').update(reversed(logs))

def get_range(start_ip: str, end_ip: str) -> List[str]:
    if is_valid_ipv4_address(start_ip) and is_valid_ipv4_address(end_ip):
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        current = start[:]
        
        ip_range = []
        
        while current <= end:
            ip = '.'.join(map(str, current))
            ip_range.append(ip)
            
            # Increment the IP address
            current[3] += 1
            for i in reversed(range(1, 4)):
                if current[i] == 256:
                    current[i] = 0
                    current[i - 1] += 1
                    
        return ip_range
    else:
        make_log("-> Insira os dados corretamente")

def is_reachable_worker(ip):
    try:
        reachable = False

        # Ping the IP address to check if it's reachable
        result = ping(ip,timeout=1, count=2)
                    
        if result.success():
            reachable = True
        else:
            reachable = False

        #Seta o ip atual
        set_current(ip)

    except subprocess.CalledProcessError:
        pass
    
    if reachable:
        make_log(f"-> Host {ip} online")
    else:
        make_log(f"-> Host {ip} offline")
    
    return (reachable, ip)

def get_reachable_hosts(ips: List[str]) -> List[str]:
    reachable_hosts = []
    non_reachable = []
    
    
    with ThreadPool(10) as pool:        
        for result in pool.map(is_reachable_worker, ips):
            reachable, ip = result

            if reachable:
                reachable_hosts.append(ip)
            else:
                non_reachable.append(ip)

    return reachable_hosts, non_reachable

def copy_folder_to_ips(folder_path, ips, sub):
    global logs

    # Get the folder name from the folder path
    folder_name = os.path.basename(folder_path)
    

    # Iterate over each IP address
    make_log(f"-> Copiando {folder_name}...")

    for ip in ips:
        #Error var
        err = ""
        
        # Create the destination folder path
        destination_path = fr"\\{ip}\c$\{folder_name}"
        
        #Seta o ip atual
        set_current(ip)
        # Copy the folder to the destination path
        try:
        # Check if the folder already exists in the destination path
            if os.path.exists(destination_path):
                if sub:
                    make_log(f"-> Substituir pasta '{folder_name}' em '{ip}'")
                    shutil.rmtree(destination_path)
                else:
                    make_log(f"-> Pasta '{folder_name}' ja existe em '{ip}'")
                    #continue
        
            shutil.copytree(folder_path, destination_path, copy_function = shutil.copy)
                
            make_log(f"-> Pasta '{folder_name}' copiada para '{ip}'")
        except Exception as e:
            err = e
            make_log(f"-> Maquina alvo: {ip} não esta disponivel")

        update_ips(ip, ips, err=err)

    make_log(f"-> Copias finalizadas")

def name_host(addr):
    try:
        return socket.gethostbyaddr(addr)[0]
    except:
        pass

def exec_script(ipi, ipf, script_path, outfile, filter):
    ips = get_range(ipi, ipf)

    logs.clear()
    make_log("-> Detectando hosts online...")
    ip_addresses, non_reachable = get_reachable_hosts(ips)
    make_log(f"-> Hosts: {len(non_reachable)} offline / {len(ip_addresses)} online")

    result = []

    for ipaddr in ip_addresses:
        #Seta o ip atual
        set_current(ipaddr)

        r = f"HOST: {ipaddr} - {name_host(ipaddr)} -> {execute_bat_remotely(ipaddr, script_path)}"
        if filter:
            #Filtra o resultado para aparecer apenas os hosts cujo nome de usuario esta incluso na saida do script
            if parse_filter(filter, ipaddr) in r:
                result.append(r)
        else:
            result.append(r)
        
    save_list_to_file(outfile, result)
    
    make_log(f"-> Finalizado. Salvo em {outfile}")

def start(folder_to_copy, start_ip, end_ip, ip_list, sub):
    logs.clear()
    # Get the reachable hosts within the IP range

    if not ip_list:
        make_log("-> Detectando hosts online...")
        ips = get_range(start_ip, end_ip)
    else:
        ips = ip_list
        make_log(f"-> Enviando para lista de ips em {file_name}")
        make_log("-> Detectando hosts online...")

    ip_addresses, non_reachable = get_reachable_hosts(ips)
    save_list_to_file(file_name, non_reachable)
    make_log(f"-> Hosts: {len(non_reachable)} offline / {len(ip_addresses)} online")
    
    if len(ip_addresses):
        copy_folder_to_ips(folder_to_copy, ip_addresses, sub)
    else:
        make_log("-> Nenhum host online, finalizando.")

# Event Loop to process "events" and get the "values" of the inputs

while True:
    event, values = window.read()

    if callable(event):
        event()
    
    if event in (sg.WIN_CLOSED, 'Exit'):
        break
    
    if event == "getf":
        try:
            ip_list = get_file(file_name)

            if all(ip_list):
                window['_LISTBOX_IPS'].update([f"-> {ip}" for ip in ip_list])
                make_log(f"-> Lista de ips em {file_name} carregada")
            else:
                make_log(f"-> Lista de ips em {file_name} vazia")
        except:
            make_log("-> ERRO: Arquivo invalido ou inexistente")

    if event == "start":
        logs.clear()
        sub = values["sub"]        
        t = threading.Thread(target=start, args=(values["folder"], values["ipi"], values["ipf"], ip_list, sub))
        t.daemon = True
        running_threads.append(t)
        t.start()

        if values["atl"]:
            path = values["folder_at"]
            atl_name = values["atl_name"]

            t = threading.Thread(target=criar_atalhos, args=(values["ipi"], values["ipf"], path, atl_name))
            t.daemon = True
            running_threads.append(t)
            t.start()
    
    if event == "criar":
        logs.clear()
        path = values["folder_at"]
        atl_name = values["atl_name"]

        t = threading.Thread(target=criar_atalhos, args=(values["ipi"], values["ipf"], path, atl_name))
        t.daemon = True
        running_threads.append(t)
        t.start()
    
    if event == "exec":
        ipi = values["ipi"]
        ipf = values["ipf"]
        script_path = values["script"]
        outfile = values["out_name"]

        filter = values["filter"]
        t = threading.Thread(target=exec_script, args=(ipi, ipf, script_path, outfile, filter))
        t.daemon = True
        running_threads.append(t)
        t.start()

    if event == "stop_all":
        stop_all(running_threads)
        make_log("-> Rotinas paradas")

    if event == "clear":
        ip_list.clear()
        window['_LISTBOX_IPS'].update("")

        make_log("-> Lista de ips carregados foi zerada")

window.close()
