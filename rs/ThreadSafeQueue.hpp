
#ifndef THREADSAFEQUEUE_HPP
#define THREADSAFEQUEUE_HPP

#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread.hpp>
#include <queue>

template<typename T>
class ThreadSafeQueue
{
public:
    ~ThreadSafeQueue();
    void put(T& item);

    /* this will block if the queue is empty */
    T get();

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

#endif // THREADSAFEQUEUE_HPP
