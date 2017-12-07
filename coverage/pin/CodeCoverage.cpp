#include <iostream>
#include <set>
#include <string>
#include <vector>
#include <utility>
#include <iterator>
#include <algorithm>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <unordered_set>
#include <unordered_map>

#include "pin.H"
#include "TraceFile.h"
#include "ImageManager.h"

// Pin comes with some old standard libraries.
namespace pintool {
template <typename V>
using unordered_set = std::tr1::unordered_set<V>;

template <typename K, typename V>
using unordered_map = std::tr1::unordered_map<K, V>;
}

// Tool's arguments.
static KNOB<string> KnobModuleWhitelist(KNOB_MODE_APPEND, "pintool", "w", "",
    "Add a module to the white list. If none is specified, everymodule is white-listed. Example: libTIFF.dylib");

static KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "trace.log",
    "Name of the output file. If none is specified, trace.log is used.");

// Return the file/directory name of a path.
static string base_name(const string& path)
{
#if defined(TARGET_WINDOWS)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif
    string::size_type idx = path.rfind(PATH_SEPARATOR);
    string name = (idx == string::npos) ? path : path.substr(idx + 1);
    return name;
}

// Per thread data structure. This is mainly done to avoid locking.
struct ThreadData {
    // Unique list of hit basic blocks.
    pintool::unordered_set<ADDRINT> m_block_hit;

    // Map basic a block address to its size.
    pintool::unordered_map<ADDRINT, uint16_t> m_block_size;
};

class ToolContext {
public:
    ToolContext()
    {
        PIN_InitLock(&m_loaded_images_lock);
        PIN_InitLock(&m_thread_lock);
        m_tls_key = PIN_CreateThreadDataKey(nullptr);
    }

    ThreadData* GetThreadLocalData(THREADID tid)
    {
        return static_cast<ThreadData*>(PIN_GetThreadData(m_tls_key, tid));
    }

    void setThreadLocalData(THREADID tid, ThreadData* data)
    {
        PIN_SetThreadData(m_tls_key, data, tid);
    }

    // The image manager allows us to keep track of loaded images.
    ImageManager* m_images;

    // Trace file used to log execution traces.
    TraceFile* m_trace;

    // Keep track of _all_ the loaded images.
    std::vector<LoadedImage> m_loaded_images;
    PIN_LOCK m_loaded_images_lock;

    // Thread tracking utilities.
    std::set<THREADID> m_seen_threads;
    std::vector<ThreadData*> m_terminated_threads;
    PIN_LOCK m_thread_lock;

    // Flag that indicates that tracing is enabled. Always true if there are no whitelisted images.
    bool m_tracing_enabled = true;

    // TLS key used to store per-thread data.
    TLS_KEY m_tls_key;
};

// Thread creation event handler.
static VOID OnThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    // Create a new `ThreadData` object and set it on the TLS.
    auto& context = *reinterpret_cast<ToolContext*>(v);
    context.setThreadLocalData(tid, new ThreadData);

    // Save the recently created thread.
    PIN_GetLock(&context.m_thread_lock, 1);
    {
        context.m_seen_threads.insert(tid);
    }
    PIN_ReleaseLock(&context.m_thread_lock);
}

// Thread destruction event handler.
static VOID OnThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 c, VOID* v)
{
    // Get thread's `ThreadData` structure.
    auto& context = *reinterpret_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);

    // Remove the thread from the seen threads set and add it to the terminated list.
    PIN_GetLock(&context.m_thread_lock, 1);
    {
        context.m_seen_threads.erase(tid);
        context.m_terminated_threads.push_back(data);
    }
    PIN_ReleaseLock(&context.m_thread_lock);
}

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    string img_name = base_name(IMG_Name(img));

    ADDRINT low = IMG_LowAddress(img);
    ADDRINT high = IMG_HighAddress(img);

    printf("Loaded image: %p:%p -> %s\n", (void *)low, (void *)high, img_name.c_str());

    // Save the loaded image with its original full name/path.
    PIN_GetLock(&context.m_loaded_images_lock, 1);
    {
        context.m_loaded_images.push_back(LoadedImage(IMG_Name(img), low, high));
    }
    PIN_ReleaseLock(&context.m_loaded_images_lock);

    // If the image is whitelisted save its information.
    if (context.m_images->isWhiteListed(img_name)) {
        context.m_images->addImage(img_name, low, high);

        // Enable tracing if not already enabled.
        if (!context.m_tracing_enabled)
            context.m_tracing_enabled = true;
    }
}

// Image unload event handler.
static VOID OnImageUnload(IMG img, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    context.m_images->removeImage(IMG_LowAddress(img));
}

// Basic block hit event handler.
static VOID PIN_FAST_ANALYSIS_CALL OnBasicBlockHit(THREADID tid, ADDRINT addr, UINT32 size, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    data->m_block_hit.insert(addr);
    data->m_block_size[addr] = size;
}

// Trace hit event handler.
static VOID OnTrace(TRACE trace, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    BBL bbl = TRACE_BblHead(trace);
    ADDRINT addr = BBL_Address(bbl);

    // Check if the address is inside a white-listed image.
    if (!context.m_tracing_enabled || !context.m_images->isInterestingAddress(addr))
        return;

    // For each basic block in the trace.
    for (; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        addr = BBL_Address(bbl);
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)OnBasicBlockHit,
            IARG_FAST_ANALYSIS_CALL,
            IARG_THREAD_ID,
            IARG_ADDRINT, addr,
            IARG_UINT32, BBL_Size(bbl),
            IARG_PTR, v,
            IARG_END);
    }
}

// Program finish event handler.
static VOID OnFini(INT32 code, VOID* v)
{
    auto& context = *reinterpret_cast<ToolContext*>(v);
    context.m_trace->write_string("DRCOV VERSION: 2\n");
    context.m_trace->write_string("DRCOV FLAVOR: drcov\n");
    context.m_trace->write_string("Module Table: version 2, count %u\n", context.m_loaded_images.size());
    context.m_trace->write_string("Columns: id, base, end, entry, checksum, timestamp, path\n");

    // We don't supply entry, checksum and, timestamp.
    for (unsigned i = 0; i < context.m_loaded_images.size(); i++) {
        const auto& image = context.m_loaded_images[i];
        context.m_trace->write_string("%2u, %p, %p, 0x0000000000000000, 0x00000000, 0x00000000, %s\n",
            i, (void *)image.low_, (void *)image.high_, image.name_.c_str());
    }

    // Add non terminated threads to the list of terminated threads.
    for (THREADID i : context.m_seen_threads) {
        ThreadData* data = context.GetThreadLocalData(i);
        context.m_terminated_threads.push_back(data);
    }

    // Count the global number of basic blocks.
    size_t number_of_bbs = 0;
    for (const auto& data : context.m_terminated_threads) {
        number_of_bbs += data->m_block_hit.size();
    }

    context.m_trace->write_string("BB Table: %u bbs\n", number_of_bbs);

    struct __attribute__((packed)) drcov_bb {
        uint32_t start;
        uint16_t size;
        uint16_t id;
    };

    drcov_bb tmp;

    for (const auto& data : context.m_terminated_threads) {
        for (const auto& address : data->m_block_hit) {
            auto it = std::find_if(context.m_loaded_images.begin(), context.m_loaded_images.end(), [&address](const LoadedImage& image) {
                return address >= image.low_ && address < image.high_;
            });

            if (it == context.m_loaded_images.end())
                continue;

            tmp.id = (uint16_t)std::distance(context.m_loaded_images.begin(), it);
            tmp.start = (uint32_t)(address - it->low_);
            tmp.size = data->m_block_size[address];

            context.m_trace->write_binary(&tmp, sizeof(tmp));
        }
    }
}

int main(int argc, char* argv[])
{
    cout << "CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)" << endl;

    // Initialize symbol processing
    PIN_InitSymbols();

    // Initialize PIN.
    if (PIN_Init(argc, argv)) {
        cerr << "Error initializing PIN, PIN_Init failed!" << endl;
        return -1;
    }

    // Initialize the tool context.
    ToolContext *context = new ToolContext();

    // Create a an image manager that keeps track of the loaded/unloaded images.
    context->m_images = new ImageManager();
    for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i) {
        cout << "White-listing image: " << KnobModuleWhitelist.Value(i) << endl;
        context->m_images->addWhiteListedImage(KnobModuleWhitelist.Value(i));

        // We will only enable tracing when any of the whitelisted images gets loaded.
        context->m_tracing_enabled = false;
    }

    // Create a trace file.
    cout << "Logging code coverage information to: " << KnobLogFile.ValueString() << endl;
    context->m_trace = new TraceFile(KnobLogFile.ValueString());

    // Handlers for thread creation and destruction.
    PIN_AddThreadStartFunction(OnThreadStart, context);
    PIN_AddThreadFiniFunction(OnThreadFini, context);

    // Handlers for image loading and unloading.
    IMG_AddInstrumentFunction(OnImageLoad, context);
    IMG_AddUnloadFunction(OnImageUnload, context);

    // Handlers for instrumentation events.
    TRACE_AddInstrumentFunction(OnTrace, context);

    // Handler for program exits.
    PIN_AddFiniFunction(OnFini, context);

    PIN_StartProgram();
    return 0;
}
