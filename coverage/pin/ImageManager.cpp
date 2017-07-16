#include "ImageManager.h"
#include "pin.H"

ImageManager::ImageManager()
{
    PIN_RWMutexInit(&images_lock);
}

ImageManager::~ImageManager()
{
    PIN_RWMutexFini(&images_lock);
}

VOID ImageManager::addImage(string image_name, ADDRINT lo_addr,
    ADDRINT hi_addr)
{
    PIN_RWMutexWriteLock(&images_lock);
    {
        images.insert(LoadedImage(image_name, lo_addr, hi_addr));
    }
    PIN_RWMutexUnlock(&images_lock);
}

VOID ImageManager::removeImage(ADDRINT low)
{
    PIN_RWMutexWriteLock(&images_lock);
    {
        set<LoadedImage>::iterator i = images.find(LoadedImage("", low));
        if (i != images.end()) {
            LoadedImage li = *i;
            images.erase(i);
        }
    }
    PIN_RWMutexUnlock(&images_lock);
}

VOID ImageManager::addWhiteListedImage(const std::string& image_name)
{
    whitelist.insert(image_name);
}

BOOL ImageManager::isWhiteListed(const std::string& image_name)
{
    return whitelist.find(image_name) != whitelist.end();
}

// Checks if the given address falls inside one of the white-listed images we are
// tracing.
BOOL ImageManager::isInterestingAddress(ADDRINT addr)
{
    PIN_RWMutexReadLock(&images_lock);
    {
        // If there is no white-listed image, everything is white-listed.
        if (images.empty() || (addr >= m_cached_low && addr < m_cached_high)) {
            PIN_RWMutexUnlock(&images_lock);
            return true;
        }

        auto i = images.upper_bound(LoadedImage("", addr));
        --i;

        // If the instruction address does not fall inside a valid white listed image, bail out.
        if (!(i != images.end() && i->low_ <= addr && addr < i->high_)) {
            PIN_RWMutexUnlock(&images_lock);
            return false;
        }

        // Save the matched image.
        m_cached_low = i->low_;
        m_cached_high = i->high_;
    }
    PIN_RWMutexUnlock(&images_lock);

    return true;
}
