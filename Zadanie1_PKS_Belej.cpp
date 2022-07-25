#include <pcap.h>
#include <stdio.h>


#define dlzka_riadka 16

typedef struct Ethertypes{
	unsigned int typ;
	char nazov[20];
}ETHER;

typedef struct Sapy {
	unsigned int typ;
	char nazov[20];
}SAP;

typedef struct IPProtocoly {
	unsigned int typ;
	char nazov[20];
}IPP;

typedef struct TCPPorty {
	unsigned int typ;
	char nazov[20];
}TCP_PORT;

typedef struct UDPPorty {
	unsigned int typ;
	char nazov[20];
}UDP_PORT;

typedef struct ARP_ramec {
	int poradove_cislo;
	int velkost;
	const u_char* ramec;
	u_char typ;
}ARPR;

typedef struct ICMP_ramec {
	int poradove_cislo;
	int velkost;
	const u_char* ramec;
	u_char sprava;
}ICMPR;

typedef struct RamceSoSpojenim {
	int poradove_cislo;
	int velkost;
	const u_char* ramec;
}RSS;

typedef struct KompletKomunikacia {
	int s_port;
	int d_port;
	RSS* syn_ramec;
	RSS** kom_ramce;
}KK;

//funkcia na prepocitanie dlzky ramca
int zisti_real_dlzku(int dlzka) {
	if (dlzka >= 60)
		return dlzka + 4;
	else
		return 64;
}
//funkcia ktorou zistime ci ide o Ethernet ramec alebo o IEEE 802.3 ramec
int zisti_typ_ramca(const u_char* packet) {
	if (((packet[12] << 8) | packet[13]) < 0x0640) {
		if (((packet[14] << 8) | packet[15]) == 0xffff) {
			return 1;
			// vracia jednotku ak je to 802.3 RAW
		}
		else if (packet[14] == 0xAA && packet[15] == 0xAA) {
			return 2;
			//vracia dvojku ak je to 802.3 LLC so SNAPom
		}
		else {
			return 3;
			//vracia trojku ak je to 802.3 LLC
		}
	}
	else {
		return 0;
		//vracia nulu ak je to Ethernet II
	}
}
//funkcia vypise do suboru jednotlive bajty ramca so zarovnanim na 16 bajtov v jednom riadku 
void vypis_obsah_ramca(int dlzka_ramca, const u_char* packet, FILE* fp) {
	//cyklus pre vypisanie jednotlivych bajtov ramca
	for (int i = 1; i < (dlzka_ramca +1); i++){ 
		fprintf(fp,"%02X ", packet[i - 1]);
		if ((i % dlzka_riadka) == 0) {
			fprintf(fp, "\n");
		}
	}
	fprintf(fp,"\n");
}
//funkcia vypise mac adresy ramca priamo z ramca podla prislusnych bajtov
void vypis_mac_adresy(const u_char* packet, FILE* fp) {
	fprintf(fp, "Zdrojova MAC adresa: %02X:%02X:%02X:%02X:%02X:%02X\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
	fprintf(fp,"Cielova MAC adresa: %02X:%02X:%02X:%02X:%02X:%02X\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
}
//funkcia na vypis udajov o ramci - dlzka ramca(aj aj), typ ramca, a vola funkciu na vypis mac adries
void vypis_ramec(int dlzka_ramca, const u_char* packet, FILE* fp) {

	//vypis dlkzky ramca cez pcap api
	fprintf(fp, "dlzka ramca poskytnuta pcap API: %ld B\n", dlzka_ramca);

	//vypis dlzky ramca po mediu
	fprintf(fp, "dlzka ramca prenasaneho po mediu: %ld B\n", zisti_real_dlzku(dlzka_ramca));

	int ramec = zisti_typ_ramca(packet);
	if (ramec == 1) {
		fprintf(fp, "IEEE 802.3 - RAW\n");
		vypis_mac_adresy(packet, fp);
	}
	else if (ramec == 2) {
		fprintf(fp, "IEEE 802.3 LLC + SNAP\n");
		vypis_mac_adresy(packet, fp);
	}
	else if (ramec == 3) {
		fprintf(fp, "IEEE 802.3 LLC\n");
		vypis_mac_adresy(packet, fp);
	}
	else if (ramec == 0) {
		fprintf(fp, "Ethernet II\n");
		vypis_mac_adresy(packet, fp);
	}
}
//funkcia pre vykonanie analyzy ramcov v bode 4a az 4f
//argumentmi je zoznam ramcov daneho typu protokolu, pole oznaceni, ci ten ramec bol uz analyzovany, celkovy pocet ramcov v zozname, typ ramcov ktory analyzujeme, a smernik na subor do ktoreho treba pisat
int analyza_ramcov_so_spojenim(RSS** ramce, char* marked_list,int pocet_ramcov,const char* typ,FILE* fp) {
	int i,j,k;
	char nekompletka = 'n'; //oznacenie, ci uz sme nasli nekompletny ramec 
	char kompletka = 'n'; //oznacenie, ci uz sme nasli kompletny ramec
	//ak su tieto oznacenia obe 'a' funkcia konci a teda vypise prave jeden kompletny ramec a prvy  nekompletny
	//pozn. odobratim podmienok suvisiacich s tymit oznaceniami vie funkcia prejst a vypisat vsetky komunikacie v zozname
	int pocet_ramcov_v_kom = 0;		//premenna oznacuje pocet ramcov, ktore patria ku konkretnej komunikacii
	KK* komunikacia = (KK*)malloc(sizeof(KK));		//struct pre konkretnu komunikaciu
	komunikacia->kom_ramce = (RSS**)malloc(sizeof(RSS*));		//zoznam komunikacnych ramcov komunikacie (ramce ine ako SYN)
		for (i = 0;i < pocet_ramcov;i++) {		//prechadzame vsetky ramce v zozname ramcov zo suboru - RSS** ramce
			if (kompletka == 'a' && nekompletka == 'a') {		//pokial sme uz nasli aj kompletnu aj nekompletnu komunikaciu, uvolni sa pridelena pamat a funkcia vracia uspech
				free(komunikacia->kom_ramce);
				free(komunikacia->syn_ramec);
				free(komunikacia);
				return 0;
			}
			if (marked_list[i] == 'u' && ramce[i]->ramec[47]==0x02) {		//hladame ramec neoznaceny a s flagom SYN pre zacatie novej komunikacie
				//hladame prvy syn paket
				komunikacia->s_port = ((ramce[i]->ramec[34] << 8) | ramce[i]->ramec[35]);		//ulozime source port komunikacie
				komunikacia->d_port = ((ramce[i]->ramec[36] << 8) | ramce[i]->ramec[37]);		//rovnako aj destination port komunikacie
				komunikacia->syn_ramec = (RSS*)malloc(sizeof(RSS));		//alokujeme pamat pre tento SYN ramec
				komunikacia->syn_ramec->poradove_cislo = ramce[i]->poradove_cislo;		//ulozime jeho poradove cislo v poradi vsetkych ramcov (pre vypis)
				komunikacia->syn_ramec->velkost = ramce[i]->velkost;		//pocet bajtov v ramci
				komunikacia->syn_ramec->ramec = (u_char*)malloc((ramce[i]->velkost));		//pridelime pamat pre bajty ramca
				memcpy((void*)komunikacia->syn_ramec->ramec, ramce[i]->ramec, ramce[i]->velkost); ////a prekopirujeme bajty ramca do listu v structe pre SYN ramec
				marked_list[i] = 'm';		//oznacime ramec ako prejdeny
				pocet_ramcov_v_kom = 0;		//inicializujeme pocet ramcov, ktore patria ku komunikacii (na zaciatku 0 lebo SYN paket je osobitne)
				//ak mame syn paket, najdeme vsetky ramce komunikacie
				for (j = i + 1;j < pocet_ramcov;j++) {
					if (marked_list[j] == 'u') {
						//ak je to ramec s "rovnaky" ako syn ramec 
						if ((((ramce[j]->ramec[34] << 8) | ramce[j]->ramec[35]) == komunikacia->s_port && ((ramce[j]->ramec[36] << 8) | ramce[j]->ramec[37]) == komunikacia->d_port) &&
							(ramce[j]->ramec[26] == komunikacia->syn_ramec->ramec[26] && ramce[j]->ramec[27] == komunikacia->syn_ramec->ramec[27] && ramce[j]->ramec[28] == komunikacia->syn_ramec->ramec[28] && ramce[j]->ramec[29] == komunikacia->syn_ramec->ramec[29]) &&
							(ramce[j]->ramec[30] == komunikacia->syn_ramec->ramec[30] && ramce[j]->ramec[31] == komunikacia->syn_ramec->ramec[31] && ramce[j]->ramec[32] == komunikacia->syn_ramec->ramec[32] && ramce[j]->ramec[33] == komunikacia->syn_ramec->ramec[33])) {
							pocet_ramcov_v_kom++;
							komunikacia->kom_ramce = (RSS**)realloc(komunikacia->kom_ramce, pocet_ramcov_v_kom * sizeof(RSS));		//rozsirujeme pamat vzdy pri najdeni noveho ramca komunikacie na velkost pre pocet ramcov 
							komunikacia->kom_ramce[pocet_ramcov_v_kom - 1] = ramce[j];
							marked_list[j] = 'm';
						}
						//alebo ak to je "odpovedovy" ramec
						else if ((((ramce[j]->ramec[34] << 8) | ramce[j]->ramec[35]) == komunikacia->d_port && ((ramce[j]->ramec[36] << 8) | ramce[j]->ramec[37]) == komunikacia->s_port) &&
							(ramce[j]->ramec[26] == komunikacia->syn_ramec->ramec[30] && ramce[j]->ramec[31] == komunikacia->syn_ramec->ramec[27] && ramce[j]->ramec[32] == komunikacia->syn_ramec->ramec[28] && ramce[j]->ramec[33] == komunikacia->syn_ramec->ramec[29]) &&
							(ramce[j]->ramec[30] == komunikacia->syn_ramec->ramec[26] && ramce[j]->ramec[27] == komunikacia->syn_ramec->ramec[31] && ramce[j]->ramec[28] == komunikacia->syn_ramec->ramec[32] && ramce[j]->ramec[29] == komunikacia->syn_ramec->ramec[33])) {
							pocet_ramcov_v_kom++;
							komunikacia->kom_ramce = (RSS**)realloc(komunikacia->kom_ramce, pocet_ramcov_v_kom * sizeof(RSS));
							komunikacia->kom_ramce[pocet_ramcov_v_kom - 1] = ramce[j];
							marked_list[j] = 'm';
						}
					}
				}
				//po prejdeni vsetkych ramcov zo zoznamu a najdeni teda vsetkych ktore ku komunikacii patria pozerame ci je kompletna alebo nekompletna (spravne/nespravne ukoncena)
				//analyza ramcov komunikacie
				
				if ((komunikacia->kom_ramce[0]->ramec[47] == 0x12) && (komunikacia->kom_ramce[1]->ramec[47] == 0x10)) {		//ak su prve 2 spravne --> SYN+ACK a ACK
					if (komunikacia->kom_ramce[pocet_ramcov_v_kom - 1]->ramec[47] == 0x10) {	//posledny je ack --> komunikacia je spravne zacata/nadviazana a ideme sledovat ako je to ukoncene
						//moznost ak je 4-way FIN handshake
						if (komunikacia->kom_ramce[pocet_ramcov_v_kom - 2]->ramec[47] == 0x11 && komunikacia->kom_ramce[pocet_ramcov_v_kom - 3]->ramec[47] == 0x10 && komunikacia->kom_ramce[pocet_ramcov_v_kom - 4]->ramec[47] == 0x11) {
							//vypis ramcov najprv osobitne syn ramec a potom vsetky ramce v komunikacii 
							if (kompletka == 'n') {
								fprintf(fp, "KOMPLETNA KOMUNIKACIA\n");
								fprintf(fp, "Ramec %d\n", komunikacia->syn_ramec->poradove_cislo);
								vypis_ramec(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "IPv4\n");
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
								fprintf(fp, "TCP\n");
								fprintf(fp, "%s\n", typ);
								fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
								vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "\n");
								for (k = 0;k < pocet_ramcov_v_kom;k++) {
									fprintf(fp, "Ramec %d\n", komunikacia->kom_ramce[k]->poradove_cislo);
									vypis_ramec(ramce[k]->velkost, komunikacia->kom_ramce[k]->ramec, fp);
									fprintf(fp, "IPv4\n");
									fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
									fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
									fprintf(fp, "TCP\n");
									fprintf(fp, "%s\n", typ);
									vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
									fprintf(fp, "\n");
								}
								kompletka = 'a';		//nastavime flag na 'a' --> nasli sme kompletnu komunikaciu 
							}
						}
						//moznost ak je 3-way FIN handshake
						else if (komunikacia->kom_ramce[pocet_ramcov_v_kom - 2]->ramec[47] == 0x11 && komunikacia->kom_ramce[pocet_ramcov_v_kom - 3]->ramec[47] == 0x11) {
							if (kompletka == 'n') {
								fprintf(fp, "KOMPLETNA KOMUNIKACIA\n");
								fprintf(fp, "Ramec %d\n", komunikacia->syn_ramec->poradove_cislo);
								vypis_ramec(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "IPv4\n");
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
								fprintf(fp, "TCP\n");
								fprintf(fp, "%s\n", typ);
								fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
								vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "\n");
								for (k = 0;k < pocet_ramcov_v_kom;k++) {
									fprintf(fp, "Ramec %d\n", komunikacia->kom_ramce[k]->poradove_cislo);
									vypis_ramec(ramce[k]->velkost, komunikacia->kom_ramce[k]->ramec, fp);
									fprintf(fp, "IPv4\n");
									fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
									fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
									fprintf(fp, "TCP\n");
									fprintf(fp, "%s\n", typ);
									fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
									vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
									fprintf(fp, "\n");
								}
								kompletka = 'a';
							}
						}
						//ak komunikacia nema ani 3-way ani 4-way handshake na konci je neuplna
						else {
							if (nekompletka == 'n') {
								fprintf(fp, "NEKOMPLETNA KOMUNIKACIA\n");
								fprintf(fp, "Ramec %d\n", komunikacia->syn_ramec->poradove_cislo);
								vypis_ramec(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "IPv4\n");
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
								fprintf(fp, "TCP\n");
								fprintf(fp, "%s\n", typ);
								fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
								vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "\n");
								for (k = 0;k < pocet_ramcov_v_kom;k++) {
									fprintf(fp, "Ramec %d\n", komunikacia->kom_ramce[k]->poradove_cislo);
									vypis_ramec(ramce[k]->velkost, komunikacia->kom_ramce[k]->ramec, fp);
									fprintf(fp, "IPv4\n");
									fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
									fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
									fprintf(fp, "TCP\n");
									fprintf(fp, "%s\n", typ);
									fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
									vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
									fprintf(fp, "\n");
								}
								nekompletka = 'a';
							}
						}
					}
					//koniec resetom 
					else if (((komunikacia->kom_ramce[pocet_ramcov_v_kom - 1]->ramec[47] & 4) >> 2) == 1) {		//testujeme, ci ma posledny ramec RST flag teda pomocou bitoveho prieniku zistime ci na mieste RST je jednotka = RST alebo nie
						if (kompletka == 'n') {
							fprintf(fp, "KOMPLETNA KOMUNIKACIA\n");
							fprintf(fp, "Ramec %d\n", komunikacia->syn_ramec->poradove_cislo);
							vypis_ramec(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
							fprintf(fp, "IPv4\n");
							fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
							fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
							fprintf(fp, "TCP\n");
							fprintf(fp, "%s\n", typ);
							fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
							vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
							fprintf(fp, "\n");
							for (k = 0;k < pocet_ramcov_v_kom;k++) {
								fprintf(fp, "Ramec %d\n", komunikacia->kom_ramce[k]->poradove_cislo);
								vypis_ramec(ramce[k]->velkost, komunikacia->kom_ramce[k]->ramec, fp);
								fprintf(fp, "IPv4\n");
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
								fprintf(fp, "TCP\n");
								fprintf(fp, "%s\n", typ);
								fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
								vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "\n");
							}
							kompletka = 'a';
						}
					}
					//ak koniec nie je ani reset
					else {
						if (nekompletka == 'n') {
							fprintf(fp, "NEKOMPLETNA KOMUNIKACIA\n");
							fprintf(fp, "Ramec %d\n", komunikacia->syn_ramec->poradove_cislo);
							vypis_ramec(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
							fprintf(fp, "IPv4\n");
							fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
							fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
							fprintf(fp, "TCP\n");
							fprintf(fp, "%s\n", typ);
							fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (komunikacia->syn_ramec->ramec[34] << 8) | komunikacia->syn_ramec->ramec[35], (komunikacia->syn_ramec->ramec[36] << 8) | komunikacia->syn_ramec->ramec[37]);
							vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
							fprintf(fp, "\n");
							for (k = 0;k < pocet_ramcov_v_kom;k++) {
								fprintf(fp, "Ramec %d\n", komunikacia->kom_ramce[k]->poradove_cislo);
								vypis_ramec(ramce[k]->velkost, komunikacia->kom_ramce[k]->ramec, fp);
								fprintf(fp, "IPv4\n");
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[26], komunikacia->syn_ramec->ramec[27], komunikacia->syn_ramec->ramec[28], komunikacia->syn_ramec->ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", komunikacia->syn_ramec->ramec[30], komunikacia->syn_ramec->ramec[31], komunikacia->syn_ramec->ramec[32], komunikacia->syn_ramec->ramec[33]);
								fprintf(fp, "TCP\n");
								fprintf(fp, "%s\n", typ);
								vypis_obsah_ramca(komunikacia->syn_ramec->velkost, komunikacia->syn_ramec->ramec, fp);
								fprintf(fp, "\n");
							}
							nekompletka = 'a';
						}
					}
				}
			}
		}
		//pri moznosti ze sme nenasli bud kompletnu alebo nekompletnu (pripadne ani jednu) komunikaciu uvolnime pridelenu pamat a vraciame jendotku
		free(komunikacia->kom_ramce);
		free(komunikacia);
		return 1;
}

int main() {
	char temp[30];
	int j, k;

	//nacitanie ethertypov******************************************* 
	FILE* ether;
	ether = fopen("ethertypes.txt", "r");
	int lines_ether = 0;
	while (fscanf(ether, " %[^\n]", temp) != EOF) {
		lines_ether++;
	}
	fseek(ether, 0, SEEK_SET);
	ETHER** ethert = (ETHER**)malloc(lines_ether*sizeof(ETHER*));
	for (k = 0;k < lines_ether;k++) {
		ethert[k] = (ETHER*)malloc(sizeof(ETHER));
	}
	for (j = 0;j < lines_ether;j++){
		fscanf(ether, "%X %[^\n]",&ethert[j]->typ,&ethert[j]->nazov);
	}
	fclose(ether);
	//nacitanie ethertypov*******************************************


	//nacitanie sapov************************************************
	FILE* sap_file;
	sap_file = fopen("sapy.txt", "r");
	int lines_sap = 0;
	while (fscanf(sap_file, " %[^\n]", temp) != EOF) {
		lines_sap++;
	}
	fseek(sap_file, 0, SEEK_SET);
	SAP** sapy = (SAP**)malloc(lines_sap * sizeof(SAP*));
	for (k = 0;k < lines_sap;k++) {
		sapy[k] = (SAP*)malloc(sizeof(SAP));
	}
	for (j = 0;j < lines_sap;j++) {
		fscanf(sap_file, "%X %[^\n]", &sapy[j]->typ, &sapy[j]->nazov);
	}
	fclose(sap_file);
	//nacitanie sapov************************************************

	//nacitanie tcp portov*******************************************
	FILE* tcp_porty_file;
	tcp_porty_file = fopen("tcp.txt", "r");
	int lines_tcp = 0;
	while (fscanf(tcp_porty_file, " %[^\n]", temp) != EOF) {
		lines_tcp++;
	}
	fseek(tcp_porty_file, 0, SEEK_SET);
	TCP_PORT** tcp_porty = (TCP_PORT**)malloc(lines_tcp * sizeof(TCP_PORT*));
	for (k = 0;k < lines_tcp;k++) {
		tcp_porty[k] = (TCP_PORT*)malloc(sizeof(TCP_PORT));
	}
	for (j = 0;j < lines_tcp;j++) {
		fscanf(tcp_porty_file, "%X %[^\n]", &tcp_porty[j]->typ, &tcp_porty[j]->nazov);
	}
	fclose(tcp_porty_file);
	//nacitanie tcp portov*******************************************

	//nacitanie udp portov*******************************************
	FILE* udp_porty_file;
	udp_porty_file = fopen("udp.txt", "r");
	int lines_udp = 0;
	while (fscanf(udp_porty_file, " %[^\n]", temp) != EOF) {
		lines_udp++;
	}
	fseek(udp_porty_file, 0, SEEK_SET);
	UDP_PORT** udp_porty = (UDP_PORT**)malloc(lines_udp * sizeof(UDP_PORT*));
	for (k = 0;k < lines_udp;k++) {
		udp_porty[k] = (UDP_PORT*)malloc(sizeof(UDP_PORT));
	}
	for (j = 0;j < lines_udp;j++) {
		fscanf(udp_porty_file, "%X %[^\n]", &udp_porty[j]->typ, &udp_porty[j]->nazov);
	}
	fclose(udp_porty_file);
	//nacitanie udp portov*******************************************

	//nacitanie IP protokolov****************************************
	FILE* ip_file;
	ip_file = fopen("ipprotokoly.txt", "r");
	int lines_ip = 0;
	while (fscanf(ip_file, " %[^\n]", temp) != EOF) {
		lines_ip++;
	}
	fseek(ip_file, 0, SEEK_SET);
	IPP** ip_prot = (IPP**)malloc(lines_ip * sizeof(IPP*));
	for (k = 0;k < lines_ip;k++) {
		ip_prot[k] = (IPP*)malloc(sizeof(IPP));
	}
	for (j = 0;j < lines_ip;j++) {
		fscanf(ip_file, "%X %[^\n]", &ip_prot[j]->typ, &ip_prot[j]->nazov);
	}
	fclose(ip_file);
	//nacitanie IP protokolov****************************************


	printf("Zadajte meno suboru ktory chcete analyzovat\n");
	char subor[100];		//vytvorime staticke pole pre input nazvu suboru, ktory vlastne chceme analyzovat
	scanf("%s", subor);
	
	char chybovy_buffer[PCAP_ERRBUF_SIZE];		//rovnako potrebujeme ako argument do funkcie error_buffer
	struct pcap_pkthdr* hlavicka;
	const u_char* ramec;
	pcap_t* handle;
	//v pcapovej premennej handle (zauzivana terminologia) je ulozeny pcap dump zo vstupom zadaneho suboru 
	
	int pocitadlo;		//counter pre poradie packetov
	int koniec;		//flag pre kontrolu konca suboru
	FILE* fp;
	fp = fopen("vystup.txt", "w");
	int vysledok;

	//polia pre adresy ktore potrebujeme pre najdenie najpocetnejsej prijimacej adresy a vypis vsetkych IP
	u_char** adresy = (u_char**)malloc(sizeof(u_char*));
	int* pocty_adries = (int*)malloc(sizeof(int));
	int pocet_adr = 0;
	int max = 0 ;
	int pozicia = 0;

	//polia potrebne pre analyzu ICMP ramcov -- uvolnuju sa pri ukoncovani programu cez q
	ICMPR** icmp_ramce = (ICMPR**)malloc(sizeof(ICMPR*));
	int pocet_icmp = 0;
	char* marked_icmp_list = (char*)malloc(sizeof(char));
	int pocet_icmp_kom = 0;

	//polia potrebne pre analyzu ARP ramcov
	ARPR** arp_ramce = (ARPR**)malloc(sizeof(ARPR*));
	int pocet_arp = 0;
	char* marked_arp_list = (char*)malloc(sizeof(char));
	int pocet_arp_kom = 0;

	//polia pre port -- potrebne pre analyzu TFTP ramcov 
	u_char* port = (u_char*)malloc(2 * sizeof(u_char));
	int pocet_tftp_kom = 0;

	//polia potrebne pre analyzu ramcov a komunikacii so spojenim
	RSS** s_ramce = (RSS**)malloc(sizeof(RSS*));
	int pocet_s_ramcov = 0;
	char* marked_s_ramce_list = (char*)malloc(sizeof(char));
	
	//teraz sa spusti kvazi menu, v ktorom definujeme ktoru cast zadania chceme vykonat podla cisel 
	while (true)
	{
		printf("\n**********************************************************\n");
		printf("\nZadajte prislusne cislo pre konkretnu ulohu zo zadania.\n");
		printf("Pre ukoncenie zadajte 'q'\n");
		//otvaranie musi byt v cykle
		handle = pcap_open_offline(subor, chybovy_buffer);
											
		pocitadlo = 0;
		char vstup;
		scanf(" %c", &vstup);
		switch (vstup)
		{
			case 'q':
				//pri ukoncovani suboru uvolnime vsetku pamat ktoru sme alokovali 
				fclose(fp);
				//free ethertypy
				for (k = 0;k < lines_ether;k++) {
					free(ethert[k]);
				}
				free(ethert);
				//free sapy
				for (k = 0;k < lines_sap;k++) {
					free(sapy[k]);
				}
				free(sapy);
				//free tcp porty
				for (k = 0;k < lines_tcp;k++) {
					free(tcp_porty[k]);
				} 
				free(tcp_porty);
				//free udp porty
				for (k = 0;k < lines_udp;k++) {
					free(udp_porty[k]);
				}
				free(udp_porty);
				//free ip protokoly
				for (k = 0;k < lines_ip;k++) {
					free(ip_prot[k]);
				}
				free(ip_prot);

				//uvolnime vsetky ulozene IP adresy ako aj ich pocty
				for (k = 0;k < pocet_adr;k++) {
					free(adresy[k]);
				}
				free(adresy);
				free(pocty_adries);

				//uvolnime arp_ramce
				for (k = 0;k < pocet_arp;k++) {
					free((void*)arp_ramce[k]->ramec);
				}
				free(arp_ramce);
				free(marked_arp_list);

				//uvolnime icmp ramce
				for (k = 0;k < pocet_icmp;k++) {
					free((void*)icmp_ramce[k]->ramec);
				}
				free(icmp_ramce);
				free(marked_icmp_list);

				free(port);
				return 0;

			case '3':
				fprintf(fp,"VYPIS BODU 3\n");
				//prehladavame cely subor (zachyteny a nacitany pcap)
				while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0)
				{
					//pomocou pomocnej funkcie zistime o aky ramec ide ---> ETH II. , 802.33...
					vysledok = zisti_typ_ramca(ramec);
					fprintf(fp, "ramec %d\n", ++pocitadlo);
					//funkcia vypis_ramec vypise do suboru vsetky potrebne udaje o ramci z prveho a druheho bodu --> dlzku ramca, o aky ramec ide, MAC adresy
					vypis_ramec(hlavicka->caplen, ramec,fp);
					//v tomto switchi podla typu ramce zistujeme porovnavanim s externymi subormi, aky je vnoreny protokol na sietovej vrstve nasledne aj aky je protokol/port 
					switch (vysledok){
						int i;
						case 0:
							for (i = 0;i < lines_ether;i++) {
								if (((ramec[12] << 8) | ramec[13]) == ethert[i]->typ) {
									fprintf(fp, "%s\n", ethert[i]->nazov);
									//ak je ramec IPv4 vypisujeme aj IP adresy robime zaznam o IP adresach
									if (ethert[i]->typ == 0x800) {
										fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
										fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);

										//zistime a vypiseme protokol vnoreny v IP pakete
										for (int i = 0;i < lines_ip;i++) {
											if (ramec[23] == ip_prot[i]->typ) {
												fprintf(fp, "%s\n", ip_prot[i]->nazov);
												//ak je to TCP hladame ci pozna ext. subor porty 
												if (ip_prot[i]->typ == 0x06) {
													for (int j = 0;j < lines_tcp;j++) {
														if ((ramec[34] << 8 | ramec[35]) == tcp_porty[j]->typ)
															fprintf(fp, "Source port: %d %s\n", tcp_porty[j]->typ,tcp_porty[j]->nazov);
														if ((ramec[36] << 8 | ramec[37]) == tcp_porty[j]->typ)
															fprintf(fp, "Destination port: %d %s\n", tcp_porty[j]->typ, tcp_porty[j]->nazov);
													}

												}
												//ak je to UDP tak rovnako ako pri TCP
												else if (ip_prot[i]->typ == 0x11) {
													for (int j = 0;j < lines_udp;j++) {
														if ((ramec[34] << 8 | ramec[35]) == udp_porty[j]->typ)
															fprintf(fp, "Source port: %d %s\n", udp_porty[j]->typ, udp_porty[j]->nazov);
														if ((ramec[36] << 8 | ramec[37]) == udp_porty[j]->typ)
															fprintf(fp, "Destination port: %d %s\n", udp_porty[j]->typ, udp_porty[j]->nazov);
													}
												}
												break;
											}
										}
										//v tejto casti sa ukladaju a pocitaju zachytene IP adresy
										char vlajka = 'n';
										//cyklus hlada zhodu medzi novou adresou a uz existujucou a ak ju najde, tak iba zvysi pocet vyskytov tejto adresy o 1
										for (int i = 0;i < pocet_adr;i++) {
											if (adresy[i][0] == ramec[30] && adresy[i][1] == ramec[31] && adresy[i][2] == ramec[32] && adresy[i][3] == ramec[33]) {
												vlajka = 'a';
												pocty_adries[i] += 1;
												break;
											}
										}
										//ak flag ostane na 'n', nova adresa je doteraz unikatna a ukladame ju na dalsie miesto do zaznamu 
										//POZN. zaznam o adresach sa realokuje pri kazdej novej unikatnej adrese. Dali sme teda vyssiu prioritu sprave pamati ako rychlosti
										if (vlajka == 'n') {
											pocet_adr++;		//zvysi sa pocet adries
											adresy = (u_char**)realloc(adresy, pocet_adr * sizeof(u_char*));	// alokuje sa miesto pre novy pocet adries vzdy +1 od poslednej velkosti, kedze sa zvacsuje pri kazdej novej
											pocty_adries = (int*)realloc(pocty_adries, pocet_adr * sizeof(int));	// rovnako tak pole poctu vyskytov jednotlivych adries
											if (adresy == NULL || pocty_adries == NULL) {
												printf("Nepodarilo sa realokovat\n");
												return 1;
											}
											//alokujeme konkretne miesto pre IP adresu, naplnime/zapiseme adresu na miesto a nastavime pocet vyskytov na jednotku kedze je to nova adresa
											adresy[pocet_adr - 1] = (u_char*)malloc(4 * sizeof(u_char));
											adresy[pocet_adr - 1][0] = ramec[30];
											adresy[pocet_adr - 1][1] = ramec[31];
											adresy[pocet_adr - 1][2] = ramec[32];
											adresy[pocet_adr - 1][3] = ramec[33];
											pocty_adries[pocet_adr - 1] = 1;
										}
									}
									break;
								}
							}
							break;
						case 1:
							//ak funkcia zisti_typ_ramca vrati jednotku, je to IEEE 802.3 RAW a dalej taky ramec neanalyzujeme
							break;
						case 2:
							//2 = ramec IEEE 802.3 LLC+SNAP
							for (i = 0;i < lines_sap;i++) {
								if ((ramec[14] == sapy[i]->typ) && (ramec[15] == sapy[i]->typ)) {
									fprintf(fp, "%s\n", sapy[i]->nazov);
									break;
								}
							}
							fprintf(fp, "Protokol v SNAP hlavicke: %x\n", (ramec[20] << 8 | ramec[21]));
							break;
						case 3:
							//3 = ramec IEEE 802.3 LLC
							//ak ramec nie je ethernet II urcime iba jeho dsap ssap pole 
							for (i = 0;i < lines_sap;i++) {
								if ((ramec[14] == sapy[i]->typ) && (ramec[15] == sapy[i]->typ)) {
									fprintf(fp, "%s\n", sapy[i]->nazov);
									break;
								}
							}
							break;
						default:
							break;
						}
						//na konci kazdeho ramca vypiseme jednotlive bajty
						vypis_obsah_ramca(hlavicka->caplen, ramec, fp);
						fprintf(fp, "\n");
					}
					//prechadzame na vypis a urcenie najcastejsej IP 
				fprintf(fp,"IP adresy prijimajucich uzlov:\n");
				for (int x = 0;x < pocet_adr;x++) {
					fprintf(fp, "%d.%d.%d.%d\n", adresy[x][0], adresy[x][1], adresy[x][2], adresy[x][3]);
				}
				max = pocty_adries[0];
				//prechodom cez zoznam zachytenych IP sa zisti IP s najvyssim poctom vyskytov a ulozi sa jej pocet do max a miesto do pozicia
				for (int i = 1;i < pocet_adr;i++) {
					if (pocty_adries[i] > max) {
						max = pocty_adries[i];
						pozicia = i;
					}
				}
				//finalny vypis
				fprintf(fp, "Adresa uzla s najvacsim poctom prijatych paketov: \n%d.%d.%d.%d    %d paketov\n", adresy[pozicia][0], adresy[pozicia][1], adresy[pozicia][2], adresy[pozicia][3], max);
				fprintf(fp,"\n");
				break;
			case '4':
				printf("Prosim zadajte oznacenie podulohy prislusnym malym pismenom.\n");
				char uloha;
				scanf(" %c", &uloha);

				switch (uloha)
				{
					case 'a':
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0){
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0800) && (ramec[23]==0x06) && (((ramec[34] << 8 | ramec[35]) == 0x50) | ((ramec[36] << 8 | ramec[37]) == 0x50))) {
								pocet_s_ramcov++;
								pocitadlo++;
								s_ramce = (RSS**)realloc(s_ramce, pocet_s_ramcov * sizeof(RSS));
								marked_s_ramce_list = (char*)realloc(marked_s_ramce_list, pocet_s_ramcov * sizeof(char));
								if (s_ramce == NULL || marked_s_ramce_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								s_ramce[pocet_s_ramcov - 1] = (RSS*)malloc(sizeof(RSS));
								s_ramce[pocet_s_ramcov - 1]->poradove_cislo = pocitadlo;
								s_ramce[pocet_s_ramcov - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)s_ramce[pocet_s_ramcov - 1]->ramec, ramec, hlavicka->caplen);
								s_ramce[pocet_s_ramcov - 1]->velkost = hlavicka->caplen;
								marked_s_ramce_list[pocet_s_ramcov - 1] = 'u';
							}
							else
								++pocitadlo;
						}
						analyza_ramcov_so_spojenim(s_ramce,marked_s_ramce_list,pocet_s_ramcov,"http",fp);
						break;
					case 'b':
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0800) && (ramec[23] == 0x06) && (((ramec[34] << 8 | ramec[35]) == 0x01BB) | ((ramec[36] << 8 | ramec[37]) == 0x01BB))) {
								pocet_s_ramcov++;
								pocitadlo++;
								s_ramce = (RSS**)realloc(s_ramce, pocet_s_ramcov * sizeof(RSS));
								marked_s_ramce_list = (char*)realloc(marked_s_ramce_list, pocet_s_ramcov * sizeof(char));
								if (s_ramce == NULL || marked_s_ramce_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								s_ramce[pocet_s_ramcov - 1] = (RSS*)malloc(sizeof(RSS));
								s_ramce[pocet_s_ramcov - 1]->poradove_cislo = pocitadlo;
								s_ramce[pocet_s_ramcov - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)s_ramce[pocet_s_ramcov - 1]->ramec, ramec, hlavicka->caplen);
								s_ramce[pocet_s_ramcov - 1]->velkost = hlavicka->caplen;
								marked_s_ramce_list[pocet_s_ramcov - 1] = 'u';
							}
							else
								++pocitadlo;
						}
						analyza_ramcov_so_spojenim(s_ramce, marked_s_ramce_list, pocet_s_ramcov, "https", fp);
						break;
					case 'c':
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0800) && (ramec[23] == 0x06) && (((ramec[34] << 8 | ramec[35]) == 0x17) | ((ramec[36] << 8 | ramec[37]) == 0x17))) {
								pocet_s_ramcov++;
								pocitadlo++;
								s_ramce = (RSS**)realloc(s_ramce, pocet_s_ramcov * sizeof(RSS));
								marked_s_ramce_list = (char*)realloc(marked_s_ramce_list, pocet_s_ramcov * sizeof(char));
								if (s_ramce == NULL || marked_s_ramce_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								s_ramce[pocet_s_ramcov - 1] = (RSS*)malloc(sizeof(RSS));
								s_ramce[pocet_s_ramcov - 1]->poradove_cislo = pocitadlo;
								s_ramce[pocet_s_ramcov - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)s_ramce[pocet_s_ramcov - 1]->ramec, ramec, hlavicka->caplen);
								s_ramce[pocet_s_ramcov - 1]->velkost = hlavicka->caplen;
								marked_s_ramce_list[pocet_s_ramcov - 1] = 'u';
							}
							else
								++pocitadlo;
						}
						analyza_ramcov_so_spojenim(s_ramce, marked_s_ramce_list, pocet_s_ramcov, "telnet", fp);
						break;
					case 'd':
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0800) && (ramec[23] == 0x06) && (((ramec[34] << 8 | ramec[35]) == 0x16) | ((ramec[36] << 8 | ramec[37]) == 0x16))) {
								pocet_s_ramcov++;
								pocitadlo++;
								s_ramce = (RSS**)realloc(s_ramce, pocet_s_ramcov * sizeof(RSS));
								marked_s_ramce_list = (char*)realloc(marked_s_ramce_list, pocet_s_ramcov * sizeof(char));
								if (s_ramce == NULL || marked_s_ramce_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								s_ramce[pocet_s_ramcov - 1] = (RSS*)malloc(sizeof(RSS));
								s_ramce[pocet_s_ramcov - 1]->poradove_cislo = pocitadlo;
								s_ramce[pocet_s_ramcov - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)s_ramce[pocet_s_ramcov - 1]->ramec, ramec, hlavicka->caplen);
								s_ramce[pocet_s_ramcov - 1]->velkost = hlavicka->caplen;
								marked_s_ramce_list[pocet_s_ramcov - 1] = 'u';
							}
							else
								++pocitadlo;
						}
						analyza_ramcov_so_spojenim(s_ramce, marked_s_ramce_list, pocet_s_ramcov, "ssh", fp);
						break;
					case 'e':
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0800) && (ramec[23] == 0x06) && (((ramec[34] << 8 | ramec[35]) == 0x15) | ((ramec[36] << 8 | ramec[37]) == 0x15))) {
								pocet_s_ramcov++;
								pocitadlo++;
								s_ramce = (RSS**)realloc(s_ramce, pocet_s_ramcov * sizeof(RSS));
								marked_s_ramce_list = (char*)realloc(marked_s_ramce_list, pocet_s_ramcov * sizeof(char));
								if (s_ramce == NULL || marked_s_ramce_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								s_ramce[pocet_s_ramcov - 1] = (RSS*)malloc(sizeof(RSS));
								s_ramce[pocet_s_ramcov - 1]->poradove_cislo = pocitadlo;
								s_ramce[pocet_s_ramcov - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)s_ramce[pocet_s_ramcov - 1]->ramec, ramec, hlavicka->caplen);
								s_ramce[pocet_s_ramcov - 1]->velkost = hlavicka->caplen;
								marked_s_ramce_list[pocet_s_ramcov - 1] = 'u';
							}
							else
								++pocitadlo;
						}
						analyza_ramcov_so_spojenim(s_ramce, marked_s_ramce_list, pocet_s_ramcov, "ftp-control", fp);
						break;
					case 'f':
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0800) && (ramec[23] == 0x06) && (((ramec[34] << 8 | ramec[35]) == 0x14) | ((ramec[36] << 8 | ramec[37]) == 0x14))) {
								pocet_s_ramcov++;
								pocitadlo++;
								s_ramce = (RSS**)realloc(s_ramce, pocet_s_ramcov * sizeof(RSS));
								marked_s_ramce_list = (char*)realloc(marked_s_ramce_list, pocet_s_ramcov * sizeof(char));
								if (s_ramce == NULL || marked_s_ramce_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								s_ramce[pocet_s_ramcov - 1] = (RSS*)malloc(sizeof(RSS));
								s_ramce[pocet_s_ramcov - 1]->poradove_cislo = pocitadlo;
								s_ramce[pocet_s_ramcov - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)s_ramce[pocet_s_ramcov - 1]->ramec, ramec, hlavicka->caplen);
								s_ramce[pocet_s_ramcov - 1]->velkost = hlavicka->caplen;
								marked_s_ramce_list[pocet_s_ramcov - 1] = 'u';
							}
							else
								++pocitadlo;
						}
						analyza_ramcov_so_spojenim(s_ramce, marked_s_ramce_list, pocet_s_ramcov, "ftp-data", fp);
						break;
					case 'g':
						fprintf(fp, "VYPIS BODU 4g - ANALYZA TFTP KOMUNIKACII\n");
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							//hladame prvy request v subore
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x800) && (ramec[23] == 0x11) && ((ramec[36] << 8) | ramec[37]) == 0x45) {
								fprintf(fp, "KOMUNIKACIA c. %d\n\n", ++pocet_tftp_kom);
								*port = ramec[34];	
								*(port + 1) = ramec[35];//ulozime si source port ktory potom musia mat ako Dport alebo Sport vsetky ramce komunikacie
								fprintf(fp,"Ramec %d\n", ++pocitadlo);
								fprintf(fp, "Opcode: %02X\n", ramec[43]);
								vypis_ramec(hlavicka->caplen, ramec, fp);
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);
								fprintf(fp, "UDP\n");
								fprintf(fp, "Zdrojovy port: %d\nCielovy port: 69\n", *port << 8 | *(port+1));
								vypis_obsah_ramca(hlavicka->caplen, ramec, fp);
								fprintf(fp, "\n");

								char vlajka = 'n';	//potrebujeme pre urcenie ako sa ukoncila komunikacia 
								//prechadzame dalej
								while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
									vysledok = zisti_typ_ramca(ramec);
									//najprv filtrujeme iba udp
									if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x800) && (ramec[23] == 0x11)) {
										//nasledne hladame bud error ramec ktory ukoncuje komunikaciu alebo data ramec s mensou velkostou ktory rovnako oznacuje koniec komunikacie
										if ((ramec[43] == 0x03 && hlavicka->caplen != 558) || (ramec[43] == 0x05 && hlavicka->caplen == 65)){
											//ak je to ukoncenie klasicke pomocou maleho data ramca tak si to oznacime 
											if (ramec[43] == 0x03)
												vlajka = 'a';
											fprintf(fp, "Ramec %d\n", ++pocitadlo);
											fprintf(fp, "Opcode: %02X\n", ramec[43]);
											vypis_ramec(hlavicka->caplen, ramec, fp);
											fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
											fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);
											fprintf(fp, "UDP\n");
											fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (ramec[34] << 8) | ramec[35], (ramec[36] << 8) | ramec[37]);
											vypis_obsah_ramca(hlavicka->caplen, ramec, fp);
											fprintf(fp, "\n");
											break;
										}
										//ak to nie je ukoncenie ale komunikacne ramce s obsahom resp. acknowledgmentom tak ich vypisujeme
										else if ((ramec[34]== *port && ramec[35] == *(port+1)) || (ramec[36] == *port && ramec[37] == *(port + 1))) {
											fprintf(fp, "Ramec %d\n", ++pocitadlo);
											fprintf(fp, "Opcode: %02X\n", ramec[43]);
											vypis_ramec(hlavicka->caplen, ramec, fp);
											fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
											fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);
											fprintf(fp, "UDP\n");
											fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (ramec[34] << 8) | ramec[35], (ramec[36] << 8) | ramec[37]);
											vypis_obsah_ramca(hlavicka->caplen, ramec, fp);
											fprintf(fp, "\n");
										}
									}
									
									else 
										++pocitadlo;
								}
								//ukoncenie datovym paketom ma za sebou zvacsa este jeden acknowledgment paket ktory potrebujeme ku komunikacii vypisat
								//toto riesenie je predpojate a teda predpoklada ze odpoved v podobe ack ramca pride okamzite a teda ze medzi ramcom data ktory oznacuje koniec a ack ramcom nie su ine ramce
								if (vlajka == 'a') {
									if ((((ramec[12] << 8) | ramec[13]) == 0x800) && ramec[23] == 0x11) {
										pcap_next_ex(handle, &hlavicka, &ramec);
										fprintf(fp, "Ramec %d\n", ++pocitadlo);
										fprintf(fp, "Opcode: %02X\n", ramec[43]);
										vypis_ramec(hlavicka->caplen, ramec, fp);
										fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
										fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);
										fprintf(fp, "UDP\n");
										fprintf(fp, "Zdrojovy port: %d\nCielovy port: %d\n", (ramec[34] << 8) | ramec[35], (ramec[36] << 8) | ramec[37]);
										vypis_obsah_ramca(hlavicka->caplen, ramec, fp);
										fprintf(fp, "\n");
									}
								}
							}
							else
								pocitadlo++;
						}
						break;
					case 'h':
						fprintf(fp, "VYPIS BODU 4h - ANALYZA ICMP KOMUNIKACII\n");
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x800) && ramec[23] == 0x01) {
								pocet_icmp++;
								pocitadlo++;
								icmp_ramce = (ICMPR**)realloc(icmp_ramce, pocet_icmp * sizeof(ICMPR));
								marked_icmp_list = (char*)realloc(marked_icmp_list, pocet_icmp * sizeof(char));
								if (icmp_ramce == NULL || marked_icmp_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								icmp_ramce[pocet_icmp - 1] = (ICMPR*)malloc(sizeof(ICMPR));
								icmp_ramce[pocet_icmp - 1]->poradove_cislo = pocitadlo;
								icmp_ramce[pocet_icmp - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)icmp_ramce[pocet_icmp - 1]->ramec, ramec, hlavicka->caplen);
								icmp_ramce[pocet_icmp - 1]->sprava = ramec[34];
								icmp_ramce[pocet_icmp - 1]->velkost = hlavicka->caplen;
								marked_icmp_list[pocet_icmp - 1] = 'u';
							}
							else
								pocitadlo++;
						}
						pocet_icmp_kom = 0;
						for (int i = 0;i < pocet_icmp;i++) {

							if (marked_icmp_list[i] == 'u' && icmp_ramce[i]->sprava == 0x08) {
								fprintf(fp, "Spojenie c.%d\n\n", ++pocet_icmp_kom);
								fprintf(fp, "Ramec %d --------- ", icmp_ramce[i]->poradove_cislo);
								fprintf(fp, "Typ spravy: Echo Request\n");
								vypis_ramec(icmp_ramce[i]->velkost, ramec, fp);
								fprintf(fp, "ICMP\n");
								fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
								fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);
								vypis_obsah_ramca(icmp_ramce[i]->velkost, ramec, fp);
								fprintf(fp, "\n");
								marked_icmp_list[i] = 'm';
								for (int j = i + 1;j < pocet_icmp;j++) {
									if (marked_icmp_list[j] == 'u')
										if (icmp_ramce[i]->ramec[26] == icmp_ramce[j]->ramec[30] && icmp_ramce[i]->ramec[27] == icmp_ramce[j]->ramec[31] && icmp_ramce[i]->ramec[28] == icmp_ramce[j]->ramec[32] && icmp_ramce[i]->ramec[29] == icmp_ramce[j]->ramec[33]) {
											fprintf(fp, "Ramec %d --------- ", icmp_ramce[j]->poradove_cislo);
											switch (icmp_ramce[j]->sprava)
											{
											case 0x00:
												fprintf(fp, "Typ spravy: Echo Reply\n");
												break;
											case 0x03:
												fprintf(fp, "Typ spravy: Destination Unreachable\n");
												break;
											case 0x04:
												fprintf(fp, "Typ spravy: Source Quench\n");
												break;
											case 0x05:
												fprintf(fp, "Typ spravy: Redirect\n");
												break;
											case 0x09:
												fprintf(fp, "Typ spravy: Router Advertisement\n");
												break;
											case 0x0A:
												fprintf(fp, "Typ spravy: Router Selection\n");
												break;
											case 0x0B:
												fprintf(fp, "Typ spravy: Time exceeded\n");
												break;
											case 0x0C:
												fprintf(fp, "Typ spravy: Parameter problem\n");
												break;
											}
											vypis_ramec(icmp_ramce[j]->velkost, ramec, fp);
											fprintf(fp, "ICMP\n");
											fprintf(fp, "Zdrojova IP adresa: %d.%d.%d.%d\n", ramec[26], ramec[27], ramec[28], ramec[29]); //source 26 dest 30 
											fprintf(fp, "Cielova IP adresa: %d.%d.%d.%d\n", ramec[30], ramec[31], ramec[32], ramec[33]);
											vypis_obsah_ramca(icmp_ramce[j]->velkost, ramec, fp);
											fprintf(fp, "\n");
											marked_icmp_list[j] = 'm';
											break;
										}
								}
							}
						}
						break;
					case 'i':
						fprintf(fp, "VYPIS BODU 4i - ANALYZA ARP KOMUNIKACII\n");
						while ((koniec = pcap_next_ex(handle, &hlavicka, &ramec)) >= 0) {
							vysledok = zisti_typ_ramca(ramec);
							if (vysledok == 0 && (((ramec[12] << 8) | ramec[13]) == 0x0806)) {
								pocet_arp++;
								pocitadlo++;
								arp_ramce = (ARPR**)realloc(arp_ramce, pocet_arp * sizeof(ARPR));
								marked_arp_list = (char*)realloc(marked_arp_list, pocet_arp * sizeof(char));
								if (arp_ramce == NULL || marked_arp_list == NULL) {
									printf("Nepodarilo sa realokovat\n");
									return 1;
								}
								//alokujeme konkretne miesto pre ARP ramec, 
								arp_ramce[pocet_arp - 1] = (ARPR*)malloc(sizeof(ARPR));
								arp_ramce[pocet_arp - 1]->poradove_cislo = pocitadlo;
								arp_ramce[pocet_arp - 1]->ramec = (u_char*)malloc((hlavicka->caplen));
								memcpy((void*)arp_ramce[pocet_arp - 1]->ramec, ramec, hlavicka->caplen);
								arp_ramce[pocet_arp - 1]->typ = ramec[21];
								arp_ramce[pocet_arp - 1]->velkost = hlavicka->caplen;
								marked_arp_list[pocet_arp - 1] = 'u';
							}
							else
								pocitadlo++;
						}

						pocet_arp_kom = 0;
						for (int i = 0;i < pocet_arp;i++) {
							if (marked_arp_list[i] == 'u') {
								fprintf(fp, "Komunikacia %d:\nRamec %d\n", ++pocet_arp_kom, arp_ramce[i]->poradove_cislo);
								if (arp_ramce[i]->typ == 0x01) {
									fprintf(fp, "ARP-Request, IP adresa: %d.%d.%d.%d,",arp_ramce[i]->ramec[38], arp_ramce[i]->ramec[39], arp_ramce[i]->ramec[40], arp_ramce[i]->ramec[41]);
									fprintf(fp, " MAC Adresa: ? ? ?\nZdrojova IP : %d.%d.%d.%d,", arp_ramce[i]->ramec[28], arp_ramce[i]->ramec[29], arp_ramce[i]->ramec[30], arp_ramce[i]->ramec[31]);
									fprintf(fp, " Cielova IP: %d.%d.%d.%d\n", arp_ramce[i]->ramec[38], arp_ramce[i]->ramec[39], arp_ramce[i]->ramec[40], arp_ramce[i]->ramec[41]);
								}
								marked_arp_list[i] = 'm';
								vypis_ramec(hlavicka->caplen, arp_ramce[i]->ramec, fp);
								fprintf(fp, "ARP\n");
								vypis_obsah_ramca(hlavicka->caplen, arp_ramce[i]->ramec, fp);
								fprintf(fp, "\n");
								for (int j = i + 1;j < pocet_arp;j++) {
									if (marked_arp_list[j] == 'u' && (arp_ramce[j]->typ != arp_ramce[i]->typ) && (arp_ramce[i]->ramec[28] == arp_ramce[j]->ramec[38] && arp_ramce[i]->ramec[29] == arp_ramce[j]->ramec[39]
										&& arp_ramce[i]->ramec[30] == arp_ramce[j]->ramec[40] && arp_ramce[i]->ramec[31] == arp_ramce[j]->ramec[41])) {
										fprintf(fp, "Ramec %d\n",arp_ramce[j]->poradove_cislo);
										if (arp_ramce[j]->typ == 0x02) {
											fprintf(fp, "ARP-Reply, IP adresa: %d.%d.%d.%d,", arp_ramce[j]->ramec[28], arp_ramce[j]->ramec[29], arp_ramce[j]->ramec[30], arp_ramce[j]->ramec[31]);
											fprintf(fp, " MAC adresa: %02X %02X %02X %02X %02X %02X\n", arp_ramce[j]->ramec[22], arp_ramce[j]->ramec[23], arp_ramce[j]->ramec[24], arp_ramce[j]->ramec[25], arp_ramce[j]->ramec[26], arp_ramce[j]->ramec[27]);
											fprintf(fp, "Zdrojova IP: %d.%d.%d.%d,", arp_ramce[j]->ramec[28], arp_ramce[j]->ramec[29], arp_ramce[j]->ramec[30], arp_ramce[j]->ramec[31]);
											fprintf(fp, " Cielova IP: %d.%d.%d.%d\n", arp_ramce[j]->ramec[38], arp_ramce[j]->ramec[39], arp_ramce[j]->ramec[40], arp_ramce[j]->ramec[41]);
										}
										marked_arp_list[j] = 'm';
										vypis_ramec(hlavicka->caplen, arp_ramce[j]->ramec, fp);
										fprintf(fp, "ARP\n");
										vypis_obsah_ramca(hlavicka->caplen, arp_ramce[j]->ramec, fp);
										fprintf(fp, "\n");
										break;
									}
									else if (marked_arp_list[j] == 'u' && (arp_ramce[j]->typ == 0x01) && (arp_ramce[i]->ramec[28] == arp_ramce[j]->ramec[28] && arp_ramce[i]->ramec[29] == arp_ramce[j]->ramec[29]
										&& arp_ramce[i]->ramec[30] == arp_ramce[j]->ramec[30] && arp_ramce[i]->ramec[31] == arp_ramce[j]->ramec[31])) {
											fprintf(fp, "Ramec %d\n", arp_ramce[j]->poradove_cislo);
											fprintf(fp, "ARP-Request, IP adresa: %d.%d.%d.%d,", arp_ramce[j]->ramec[38], arp_ramce[j]->ramec[39], arp_ramce[j]->ramec[40], arp_ramce[j]->ramec[41]);
											fprintf(fp, " MAC Adresa: ? ? ?\nZdrojova IP : %d.%d.%d.%d,", arp_ramce[j]->ramec[28], arp_ramce[j]->ramec[29], arp_ramce[j]->ramec[30], arp_ramce[j]->ramec[31]);
											fprintf(fp, " Cielova IP: %d.%d.%d.%d\n", arp_ramce[j]->ramec[38], arp_ramce[j]->ramec[39], arp_ramce[j]->ramec[40], arp_ramce[j]->ramec[41]);
											marked_arp_list[j] = 'm';
											vypis_ramec(hlavicka->caplen, arp_ramce[j]->ramec, fp);
											fprintf(fp, "ARP\n");
											vypis_obsah_ramca(hlavicka->caplen, arp_ramce[j]->ramec, fp);
											fprintf(fp, "\n");
									}
								}
							}
						}

						break;
				default:
					printf("Zle zadane oznacenie ulohy. Prosim skuste znova.\n");
					break;
				}
				break;

		default:
			printf("Nespravne zadany vstup. Skuste znova.\n");
			break;
		}
	}
}
