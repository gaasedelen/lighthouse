#ifndef IMAGEMANAGER_H_
#define IMAGEMANAGER_H_

#include <string>
#include <set>

#include "pin.H"

struct LoadedImage {
    std::string name_;
    ADDRINT low_;
    ADDRINT high_;

    LoadedImage(const std::string& n = "", ADDRINT low = 0, ADDRINT high = 0)
        : name_(n)
        , low_(low)
        , high_(high)
    {
    }

    // Overloaded method to implement searches over the loaded images list
    // and also allow this class to be used on a set like STL container.
    bool operator<(const LoadedImage& rhs) const
    {
        return low_ < rhs.low_;
    }
};

class ImageManager {
private:
    // Set of module names that are allowed to be traced.
    std::set<LoadedImage> images;
    PIN_RWMUTEX images_lock;

    // Here we store the names of the images inside our white list.
    std::set<std::string> whitelist;

    // Store the last recently matched image so we can use it as a cache.
    ADDRINT m_cached_low;
    ADDRINT m_cached_high;

public:
    ImageManager();
    virtual ~ImageManager();

    VOID addWhiteListedImage(const std::string& image_name);
    BOOL isWhiteListed(const std::string& image_name);
    BOOL isInterestingAddress(ADDRINT addr);

    VOID addImage(std::string image_name, ADDRINT lo_add, ADDRINT hi_addr);
    VOID removeImage(ADDRINT low);
};

#endif /* IMAGEMANAGER_H_ */
