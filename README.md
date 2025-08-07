# TMT: Thread Monitoring Tool

TMT is a simple tool that leverages eBPF to trace and analize
the amount of threads that a targeted application uses during its execution. 


### Usage
To monitor an application with TMT, simply run
 ```
    sudo ./tmt.py my_application
 ```
By default, TMT will produce two different plots: one in which each changes in 
thread count is coherent with timestamps, and another in which the distance on
time is uniform. 

It is also possible to print to stdout intermediate information:

- --print-raw prints the raw events captured by the application
- --print-tree prints a tree of the processes that have been created
- --print-intervals prints on screen a summary of the thread alive at different timestamps


### Acknowledgements

TMT has been originally developed by [Stefano Monaldi](https://www.linkedin.com/in/stefano-monaldi-0a9553296/), 
and is now being maintained by [Marco Edoardo Santimaria](https://alpha.di.unito.it/marco-santimaria/) 
and [Robert Birke](https://alpha.di.unito.it/robert-rene-maria-birke/). 