#include <stdio.h>
#include <stdarg.h>

#include <Python.h>
#include <pcap.h>
#include <dnet.h>

#define STDBUF      1024

static int count;
static int datalink;
static int snaplen;

static pcap_t *pd;
static eth_t *eth_retrans;
PyObject *PcapError;

static void fatal(const char *format, ...)
{
    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);

    fprintf(stderr, "ERROR: %s\n", buf);
    fprintf(stderr,"Fatal Error, Quitting..\n");

    va_end(ap);

    shandler(1);
}

void shandler ( int sign )
{
    if ( sign != 0 )
        signal ( sign , &shandler );

    eth_close(eth_retrans);
    pcap_close( pd );
    fprintf( stderr, "\n");
    exit( sign );
}

void packet_retrans(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
    eth_send(eth_retrans, pkt, pkthdr->caplen);
    return;
}

void packet_listen(char * in_device, char * out_device, char * filter)
{
    struct bpf_program  fp;
    bpf_u_int32 localnet, netmask;         /* net addr holders */
    char errorbuf[PCAP_ERRBUF_SIZE];       /* buffer to put error strings in */

    fprintf( stderr, "Starting tap from %s to %s using filter:\n\t%s\n",
        in_device, out_device, filter );

    pd = pcap_open_live(in_device,
                        snaplen?snaplen:65535,
                        1,
                        500,
                        errorbuf);

    if(pd == NULL)
    {
        fatal("start_sniffing(): interface %s open: %s\n", in_device, errorbuf);
    }

    if(pcap_compile(pd, &fp, filter, 1, netmask) < 0)
    {
        fatal("start_sniffing() FSM compilation failed: \n\t%s\n"
                "PCAP command: %s\n", pcap_geterr(pd), filter);
    }

    /* set the pcap filter */
    if(pcap_setfilter(pd, &fp) < 0)
    {
        fatal("start_sniffing() setfilter: \n\t%s\n",
                pcap_geterr(pd));
    }

    /* get data link type */
    datalink = pcap_datalink(pd);

    if(datalink < 0)
    {
        fatal("OpenPcap() datalink grab: \n\t%s\n",
                pcap_geterr(pd));
    }

    if((eth_retrans = eth_open(out_device)) == NULL)
        fatal("init_retrans() eth_open failed\n");

    /* Read all packets on the device.  Continue until cnt packets read */
    if(pcap_loop(pd, count, (pcap_handler) packet_retrans, NULL) < 0)
    {
        fatal("pcap_loop: %s", pcap_geterr(pd));
        shandler( 0 );
    }
    return;
}

static PyObject* ntapy_start(PyObject* self, PyObject* args, PyObject *keywds)
{
	char * in_device;
	char * out_device;
    char * filter;

    static char *kwlist[] = {"in_device", "out_device", "filter", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss|z", kwlist, &in_device,
        &out_device, &filter)) {
        return NULL;
    }

    signal( SIGINT, &shandler );
    signal( SIGTERM, &shandler );

    /* So we can use threading in the python module */
    Py_BEGIN_ALLOW_THREADS

    packet_listen(in_device, out_device, filter);

    Py_END_ALLOW_THREADS

    return 0;
}


static PyMethodDef ModuleMethods[] =
{
     {"tap", (PyCFunction)ntapy_start, METH_VARARGS |METH_KEYWORDS, "Start network tap"},
     {NULL, NULL, 0, NULL},
};

PyMODINIT_FUNC

initntapy(void)
{
     (void) Py_InitModule("ntapy", ModuleMethods);
}
