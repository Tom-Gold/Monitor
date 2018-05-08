import threading
import psutil
import Tkinter as tk
import tkMessageBox as tkM
import time
import io
import os


class Snapshot:
    watch = True

    def __init__(self, debug=False):
        if debug:
            attr = ['name', 'username', 'status']
        else:
            attr = ['pid', 'name', 'username', 'status', 'open_files', 'create_time', 'connections']

        timestamp = time.ctime((time.time()))
        self.data = {p.pid: p.info for p in psutil.process_iter(attrs=attr)}
        self.data['Timestamp'] = timestamp


def check_closed_process(oldsnap, newsnap):
    closed_proc = {}
    for pid in oldsnap.data:
        if pid not in newsnap.data:
            closed_proc[pid] = oldsnap.data[pid]
    closed_proc['Timestamp'] = newsnap.data['Timestamp']
    closed_proc['Proc_Stat'] = "Closed"
    return closed_proc


def check_new_process(oldsnap, newsnap):
    new_proc = {}
    for pid in newsnap.data:
        if pid not in oldsnap.data:
            new_proc[pid] = newsnap.data[pid]
    new_proc['Timestamp'] = newsnap.data['Timestamp']
    new_proc['Proc_Stat'] = "New"
    return new_proc


def check_hijacked_pid(oldsnap, newsnap):
    hijacked_proc = {}
    for pid, info in oldsnap.data:
        if (pid in newsnap) and (oldsnap[pid]['name'] != newsnap[pid]['name']):
            hijacked_proc[pid] = {info, newsnap.get(pid)}
    return hijacked_proc


def log_status(stat, filename='Status_Log.txt'):
    alerts = ['Alert']
    timestamp = stat['Timestamp']
    proc_stat = stat['Proc_Stat']
    del stat['Timestamp']
    del stat['Proc_Stat']
    with io.open(filename, "a", encoding="utf-8") as f:
        for pid, val in stat.items():
            process_str = str(proc_stat) + " , " + str(timestamp) + " , " + str(pid) + " , " + str(val)
            f.write(unicode(process_str) + "\n")
            alerts.append(str(proc_stat) + ', ' + str(pid) + ', ' + val['name'])
            # f.write('%s , %s , %s , %s\n' % (proc_stat, timestamp, pid, str(val)))
    # print(alerts)
    alert_popup(alerts)


def log_proc(proc, filename='processList.txt'):
    timestamp = proc.data['Timestamp']
    del proc.data['Timestamp']
    with io.open(filename, "a", encoding="utf-8") as f:
        for pid, val in proc.data.items():
            f.write('%s , %s , %s\n' % (timestamp, pid, unicode(str(val))))


def read_proc_log(filename='processList.txt'):
    try:
        with io.open(filename, "r", encoding="utf-8") as f:
            log_list = f.readlines()
        log_list.append(filename)
        return log_list
    except IOError as e:
        print(os.strerror(e.errno))
        return False


def read_stat_log(filename='Status_Log.txt'):
    try:
        with io.open(filename, "r", encoding="utf-8") as f:
            log_list = f.readlines()
        log_list.append(filename)
        return log_list
    except IOError as e:
        print(os.strerror(e.errno))
        return False


def compromised_logs_tester(log_list):
    if log_list is False:
        return False
    filename = log_list.pop()
    result = ['OK']
    with io.open(filename, "r", encoding="utf-8") as f:
        log_list_to_test = f.readlines()
    while len(log_list_to_test) > 1 and len(log_list) > 1:
        item_in_mem = log_list.pop()
        item_on_file = log_list_to_test.pop()
        if item_in_mem != item_on_file:
            result.append('Process Manipulated' + item_on_file + ', ' + item_in_mem)
            # result.append(item_in_mem)
    if len(result) > 1:
        result.remove('OK')
        alert_popup(result)
        return True
    return False


def monitor(interval):
    while Snapshot.watch:
        current_snapshot = Snapshot()
        log_proc(current_snapshot)
        proc_log_logger = read_proc_log()
        status_log_logger = read_stat_log()
        time.sleep(interval)
        compromised_logs_tester(proc_log_logger)
        compromised_logs_tester(status_log_logger)
        new_snapshot = Snapshot()
        opened = check_new_process(current_snapshot, new_snapshot)
        if len(opened) > 2:
            log_status(opened)
        closed = check_closed_process(current_snapshot, new_snapshot)
        if len(closed) > 2:
            log_status(closed)


def alert_popup(proc_str):
    popup = tk.Tk()
    popup.title("Process Monitor")
    listbox = tk.Listbox(popup)
    counter = 1
    for item in proc_str:
        listbox.insert(counter, item)
        counter += 1
    listbox.pack()
    btn = tk.Button(popup, text="Okay", command=popup.destroy)
    btn.pack()
    popup.mainloop()

def get_log_timeframe(filename='processList.txt'):
    try:
        with io.open(filename, "r", encoding="utf-8") as f:
            log_list = f.read()
        log_list.append(filename)
        return log_list
    except IOError as e:
        print(os.strerror(e.errno))
        return False


def main():
    def set_interval(interval):
        Snapshot.watch = True
        t = threading.Thread(target=monitor, args=(interval,), name=monitor)
        t.start()

    def get_interval():
        interval_str = e1.get()
        interval = int(interval_str)
        if 1 <= interval <= 1000:
            set_interval(interval)
        else:
            tkM.showinfo("Input Error", "Please Select a Number Between 1-1000", )

    def shut_monitor():
        Snapshot.watch = False
        thread_list = threading.enumerate()
        for thread in thread_list:
            if thread.getName() is "monitor":
                thread.join()
        master.destroy()

    master = tk.Tk()
    master.title("Process Monitor")
    tk.Label(master, text="Snapshot Interval").grid(row=0)
    tk.Label(master, text="Manual Mode").grid(row=4)

    e1 = tk.Entry(master)
    e2 = tk.Entry(master)
    e3 = tk.Entry(master)

    e1.grid(row=0, column=1)
    e2.grid(row=5, column=0)
    e3.grid(row=5, column=1)

    tk.Button(master, text='Quit', command=shut_monitor).grid(row=3, column=0, pady=4)
    tk.Button(master, text='Set Interval and Run', command=get_interval).grid(row=3, column=1, pady=4)

    master.mainloop()


if __name__ == "__main__":
    main()