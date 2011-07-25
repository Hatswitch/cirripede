
#ifndef THREADSAFEQUEUE_HPP
#define THREADSAFEQUEUE_HPP

#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <queue>

template<typename T>
class ThreadSafeQueue
{
public:
    ~ThreadSafeQueue();
    void put(T& item);

    /* this will block if the queue is empty */
    T get();

    /* return true if a valid item has been copied into "item", return
     * false otherwise.
     */
    bool get_with_timeout(boost::posix_time::time_duration const &rel_time,
                          T& item);

private:
    std::deque<T> _queue;
    boost::mutex _mutex;
    boost::condition_variable _not_empty;
};


template<typename T>
ThreadSafeQueue<T>::~ThreadSafeQueue()
{
    _queue.clear();
}

template<typename T>
void
ThreadSafeQueue<T>::put(T& item)
{
    boost::unique_lock<boost::mutex> lock(_mutex);
    _queue.push_back(item);
    _not_empty.notify_one();
    return;
}

template<typename T>
T
ThreadSafeQueue<T>::get()
{
    boost::unique_lock<boost::mutex> lock(_mutex);
    while (_queue.empty()) {
        _not_empty.wait(lock);
    }
    T item = _queue.front();
    _queue.pop_front();
    return item;
}

template<typename T>
bool
ThreadSafeQueue<T>::get_with_timeout(boost::posix_time::time_duration const &rel_time,
                                     T& item)
{
    boost::unique_lock<boost::mutex> lock(_mutex);
    if (_queue.empty()) {
        if (! _not_empty.timed_wait(lock, rel_time)) {
            // timed out
            return false;
        }
        // not timed out -> make sure queue is not empty (boost says
        // timed_wait might return "spuriously"
        assert(!_queue.empty());
        // falls through
    }

    // this is safe---it's using the assignment operator = to copy
    // values of rhs object into existing object of lhs. (otoh, "T&
    // item = _queue.front()" would simply make item a reference to
    // the object on rhs, and would invalidate item after
    // _queue.pop_front().)
    item = _queue.front();
    _queue.pop_front();
    return true;
}

#endif // THREADSAFEQUEUE_HPP
