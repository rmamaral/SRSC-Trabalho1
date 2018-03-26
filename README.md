# Secure Transport for group communication
### Network and computer security first project

### Trabalho	Prático	nº	1 (v1.0,	22/Mar/2018)


#### Resumo
Neste trabalho pretende-se desenvolver um protocolo de segurança para comunicação em
grupo que designaremos por (Secure Transport for Group Communication) tendo em vista
proteger comunicações IP em modo multiponto (IP Multicast - IPMC). A implementação
permitirá estabelecer numa pilha SGCM/UDP/IPMC uma camada genérica de segurança
para transporte UDP de mensagens UDP suportado em IPMulticast. A proteção do
protocolo STGC defenderá permitirá defender quaisquer aplicações de tipologias de ataques
às comunicações tendo em conta algumas das tipologias de ataques definidas na framework
de referência X.800. Um dos aspectos relevantes do trabalho é a concepção do protocolo
STGC como serviço de segurança genérico, com comprovação de prova de conceito e a
demonstração dessa generalidade com base numa uma aplicação concreta que será usada
como demonstrador.

**1. Contexto**

A segurança de canais de comunicação em aplicações distribuídas suportadas em redes TCP/IP (ou
Internet) podem ser asseguradas por protocolos de segurança normalizados e que visam proteger as
comunicações a diferentes níveis dos serviços da pilha TCP/IP (o que se estudará em mais detalhe ao
longo da disciplina).

Por exemplo, a implementação do padrão 802.11i garante proteção logo ao nível data-link, com
autenticação de dispositivos (com base no subprotocolo EAP), controlo de acesso ao meio (com base no
protocolo 802.1x) bem como autenticidade, integridade e confidencialidade de _frames_ 802.11 em redes
WiFi (com base nos protocolos WEP, TKIP ou CCMP). O protocolo IPSec fornece garantias de
segurança para autenticidade de _endpoints_ IP a partir do protocolo IKE/ISAKMP) bem como para
confidencialidade e/ou integridade de pacotes IP (com base nos subprotocolos ESP ou AH). Finalmente,
protocolos como por exemplo TLS ou WTLS, asseguram propriedades de segurança ao nível transporte,
com proteção de autenticidade, confidencialidade e integridade de segmentos TCP encapsulados em
records TLS. Todos os protocolos mencionados utilizam primitivas e algoritmos criptográficos e
_ciphersuites_ normalizadas parametrizáveis e usadas adequadamente em cada caso na sua definição e
normalização. Dependendo do nível de suporte, garantem o estabelecimento de canais de comunicação
seguros, aos diversos níveis da pilha TCP/IP com proteção das comunicações entre principais envolvidos,
aos diferentes níveis de abordagem.

No contexto do presente trabalho pretende implementar-se um novo protocolo de segurança (que se
designará por STGC – _Secure Transport for Group Communication_ ). O desenvolvimento deste protocolo,
como camada genérica de segurança no empilhamento STGC/UDP/IPMC, permitirá que possa ser usado
por qualquer aplicação que utilize comunicação UDP suportada em IPMC (por exemplo suportada em
_sockets multicast_ ). Para implementação e demonstração da generalidade da solução será usada uma de
duas aplicações (inicialmente apenas su0ortadas e UDP/IPMC) e que podem ser encontradas nos
materiais da aula prática, nomeadamente (ver em [http://asc.di.fct.unl.pt/~hj/srsc)](http://asc.di.fct.unl.pt/~hj/srsc)) e
[http://asc.di.fct.unl.pt/~hj/srsc/aulas-praticas/TP1-components/):](http://asc.di.fct.unl.pt/~hj/srsc/aulas-praticas/TP1-components/):)

- Uma aplicação para suporte de sessões de CHAT em grupo, onde os participantes se juntam a sessões
    de CHAT associadas a grupos (endereços) IP Multicast;
- Uma aplicação para suporte de disseminação de media-streaming (na forma de filmes) para serem ser
    recebidos por um proxy local (cliente) que por sua vez os disponibiliza em tempo real para serem
    visualizados com uma ferramenta local como por exemplo o VLC
    (https://www.videolan.org/index.pt.html)

Independentemente de cada grupo optar por uma ou outra das anteriores aplicações como demonstradores
e prova de funcionamento correto e final dos desenvolvimentos do trabalho, pode também usar-se o


código fornecido em _multicast-test_ , como aplicação mais simples que pode ser usada nos testes inciais
dos desenvolvimentos, antes de se usarem as aplicações anteriores.

**2. Introdução**

O protocolo STGC deverá ser implementado como serviço genérico. Isto significa que poderá vir a ser
adoptado como proteção genérica de qualquer aplicação que comunique via transporte UDP e IPBC
(usando _sockets multicast_ ). A melhor forma de comprovar a generalidade é conseguir-se uma
implementação em que a conversão de uma aplicação inicial (como as acima indicadas) que usa sockets
UDP/IPmulticast (não seguros) passará a ficar protegida se usar o protocolo STGC, devend a conversão
ser muito simples, obrigando ao menor número de alterações no código inicial. Como inspiração isso
pode ser feito por substituição do uso de _sockets multicast_ (MulticastSockets de acordo com o suporte
java.net.MulticastSocket) por sockets seguros Multicast (que se poderão definir como
STGCMulticastSockets). Estes últimos podem estender os primeiros, de acordo com o suporte da
especificação de segurança do protocolo STGCM.

Deste modo, o trabalho será tanto mais conseguido:

- quanto menor for o impacto da conversão do código de uma aplicação não protegida (quer no
    número mínimo de linhas de código alteradas quer na minimização das alterações envolvidas) para
    que fique protegida e quanto mais configurável sejam os sockets STGCMulticastSockets;
- quanto mais flexível e parametrizáveis sejam os mecanismos de segurança subjacentes ao suporte
    criptográfico e parametrizações adoptadas para operação do protocolo STGC.
**3. Modelo de adversário para o protocolo STGC**

O protocolo STGC permitirá proteger de adversários que desencadeiam ataques às comunicações, tendo
e conta a seguinte tipologia de ataques definidos na _framework_ X.800 (estudado nas aulas teóricas). Estes
ataques podem ser concretizações de ameaças por parte de potenciais oponentes com capacidade de
acesso ao canal de comunicação e fluxos de tráfego (pilha UDP/IPMC/DataLink Layer):

- _Masquerading of principals (and their IDs)_
- _IDs will be established as identifiers in the form: “<Username>:<RFC 822 Email-Address>_
    _Ex., “Henrique Domingos”:”hj@fct.unl.pt”_
- _Message Release_
- _Message Tampering_
- _Message-Replaying_

Garantindo necessariamente as seguintes propriedades de segurança:

- _Peer-Entity Authentication_
- _Data-Origin Authentication_
- _Access-Control_
- _Connectionless confidentiality_
- _Connectionless Integrity and Selective-Field Connectionless_
**4. Protocolo STGC e seus componentes**

O protocolo STGC é constituído por duas partes distintas (a seguir apresentados como dois subprotocolos
específicos e ortogonais, embora complementares e integráveis) que designaremos por: STGC-TLP
(STGC _Transport Layer Protocol_ ) e STGC-SAP (STGC – _Session Authentication Protocol_ ).

Para a implementação do trabalho os anteriores subprotocolos serão implementados de forma
independente e em fases distintas:

**FASE 1** : desenvolvimento do subprotocolo STGC-TLP

A fase 1 é obrigatória para efeitos de entrega do trabalho prático nº 1, valendo até 15 valores.


**FASE 2:** concepção e implementação do subprotocolo STGC-SAP

A fase 2 não é obrigatória para efeitos de entrega do trabalho prático nº 1 mas a sua implementação e
entrega será valorizada até 5 valores.

A implementação dos subprotocolos indicados será feita com base na utilização de sockets datagrama
para IP Multicast e endo em conta o suporte JCE (Java Cryptographic Extension) bem como respetivos
provedores criptográficos compatíveis, particularmente o provedor BoucyCastle, de acordo com o
contexto das aulas práticas / laboratórios.

As especificações iniciais de referencia para os subprotocolos STGC-TLP (Fase 1) e STGC-SAP (Fase 2)
podem ser consultadas no documento: SRSC-TP1-EspecificacoesSGCM

**5.	Entrega	do	trabalho**

**Data	de	entrega.	** A	partir	de 9/April/2018,	Data-Limite:	13/Abril/2018.

Sugere-se	 que	 os	 grupos	organizem	 as	 agendas	 de	 trabalho	 antecipando preferencialmente	a	
entrega	 a	 partir	 de 9/Março/2018	 (2ª	 feira)	de	 modo	 a	 prepararem	 bem	 o teste	 teórico.	 De	
qualquer	modo	cada	grupo	deve	planear	a	realização	do	trabalho	de	acordo	com	a	agenda	mais	
adequada	ao	grupo.

**Materiais	 a	 entregar.	** Os alunos	 receberão	 oportunamente (via	 CLIP) indicações	
complementares	para	 entrega	do	 trabalho.	 De	 qualquer	 modo,	resumidamente, a	 entrega	
envolverá os	seguintes	elementos:

- Preparar	um arquivo	TP1-SRSC.tgz	(tar-gzip)	com	a	implementação	(código	do	projeto),	com	
    duas	subdiretorias	separadas,	uma	com	a	implementação	da	fase	1		(diretoria	STGC-F1)	 e	
    outra	com	a	implementação	completa	da	FASE	2 e	FASE	1	(STGC).	Se	ambas	as	fases	tiverem
    sido	concluídas	bastará	existir	a	diretoria	STGC	e	neste	caso	ambas	as	fases	serão	avaliadas	
    na	sua	correção	global.
- Ter o	 código (projeto) e	 o	 arquivo TGZ	 anterior	 disponíveis	 em repositório	 GITHUB	 ou	
    BITBUCKET.	Na	data	de	entrega	o	projeto	terá	que	estar	partilhado	(só	em	leitura) com	o	
    docente	de	modo	que	possam	ser clonados	 (para	verificação	e	teste	pelo	docente)	a	partir	do	
    respetivo URL	do	projeto,	na	data	limite.	A	partilha	será	feita	com:
       - hj@fct-unl.pt no	caso	do	GitHub
       - henriquejoaolopesdomingos	no	caso	do	BitBucket
- Produzir	um	relatório	(TP1-REPORT.pdf).	Este	será feito	com	base	num	formato	do	tipo	ficha-
    resumo	ou	formulário,	cujo	 _template_ será	publicado	no	sistema	CLIP)	e	que	deverá	também	
    ser	colocado	no	repositório do	projeto	numa	diretoria	 **docs.	**
- No repositório	do	projeto,	deverá	ser	incluída	toda	a	informação	(README)	para	se	proceder	
    à	clonagem	e	teste	de	execução	da	implementação	bem	como	indicações	necessárias	para	o	
    efeito.

Após	 análise	 das	 implementações	 e	 respetivo	 _reporting_ ,	podem	 haver	 trabalhos	 e	 grupos	
selecionados	que	podem	ser	objeto	de	discussão/demonstração.	Neste	caso	isso	ocorrerá	com	base	
num escalonamento	a	indicar.

**Entrega	formal	do	trabalho.	** A	partilha	dos	repositórios	com	as	entregas	finais	deverá	ser	feita	
APENAS	NA	DATA	DE	13/MARÇO.


- _No_ dia	 do	 teste	(14/MAR/2018)	os	 alunos	 terão	 que	 indicar	 ( **na	 folha	 de	 resposta	 do	**
    **teste** )	 qual	 o	 URL	 de	 clonagem	 do	 repositório	 do	 projeto,	 devendo	 constar todos	 os	
    anteriores	elementos.	A	não	indicação	do	URL	será	penalizada	na	avaliação	dos	alunos	que	
    não	o	fizerem	e	a	não	existência	do	repositório	na	data	de	13/Março/2018	será	considerada	
    como	trabalho	não	entregue.
- Deve	ter-se	em	conta	que	no	teste	(parte	com	consulta	– teste	 prático)	 haverá	 questões	
    relacionadas	com	o	contexto	de	realização	do	trabalho	bem	como	sua	implementação	por	
    parte	de	cada	grupo.
- Será	 afixado	 depois	 no	 sistema	 CLIP	 a	 comunicação	 dos	 grupos	 que	 não	 entregaram	 o	
    trabalho.



