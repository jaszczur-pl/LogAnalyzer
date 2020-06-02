#!/usr/bin/env python3
import sys
import csv
import xlsxwriter
import collections
from notify_run import Notify
import win32evtlog
from datetime import datetime, timedelta

csv_file_path = "C:\\Users\\Maciek\\Desktop\\security_report.csv"
excel_file_path = "C:\\Users\\Maciek\\Desktop\\security_report.xlsx"
workstation = "localhost"
logtype = "Security"
hand = win32evtlog.OpenEventLog(workstation, logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)
event_dictionary = {4624: "Account was successfully logged on",
                    4634: "Account was logged off",
                    4625: "Account failed to log on",
                    4608: "Windows is starting up",
                    4720: "New account was created: ",
                    4725: "Account was disabled: ",
                    4726: "Account was deleted: ",
                    4722: "Account was enabled: ",
                    4740: "Account was locked out: ",
                    4767: "Account was unlocked: "}


def write_data_to_excel(workbook, sheet_name, all_events):

    worksheet_data = workbook.add_worksheet(sheet_name)
    row = 1
    col = 0
    worksheet_data.write_row('A1', ('timestamp', 'event ID', 'message', 'user', 'source', 'computer'))
    for time, event_ID, message, user, source, computer in (all_events):
        worksheet_data.write(row, col, time)
        worksheet_data.write(row, col + 1, event_ID)
        worksheet_data.write(row, col + 2, message)
        worksheet_data.write(row, col + 3, user)
        worksheet_data.write(row, col + 4, source)
        worksheet_data.write(row, col + 5, computer)
        row +=1


def add_chart_to_excel(workbook, sheet_name, event_list):
    counter = collections.Counter(event_list)
    number_of_elements = len(counter)
    worksheet_chart = workbook.add_worksheet(sheet_name)
    row = 0
    col = 0
    for key in counter:
        worksheet_chart.write(row, col, key)
        worksheet_chart.write(row, col + 1, counter[key])
        row += 1

    pie_chart = workbook.add_chart({'type': 'pie'})

    # [sheetname, first_row, first_col, last_row, last_col].
    pie_chart.add_series({
        'name': 'Event appearances',
        'categories': [sheet_name, 0, 0, number_of_elements - 1, 0],
        'values': [sheet_name, 0, 1, number_of_elements - 1, 1],
    })

    pie_chart.set_title({'name': 'Event appearances'})
    pie_chart.set_style(10)
    worksheet_chart.insert_chart('F2', pie_chart, {'x_offset': 25, 'y_offset': 10})


def write_to_csv(all_events):
    with open(csv_file_path, mode='w') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerows(all_events)
        csv_file.close()


def read_events(date_from):
    all_events = []
    event_list = []
    events_from_date = []
    event_list_from_date = []
    event_no = 0
    while 1:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                if event.EventID in event_dictionary:
                    data = event.StringInserts
                    computer = event.ComputerName
                    message = event_dictionary.get(event.EventID)
                    event_time = str(event.TimeGenerated)

                    if event.EventID == 4624 or event.EventID == 4625:
                        user = data[5]
                    elif event.EventID == 4634:
                        user = data[1]
                    elif event.EventID == 4608:
                        user = "N/A"
                    elif event.EventID == 4720 or event.EventID == 4725 or event.EventID == 4726 \
                            or event.EventID == 4722 or event.EventID == 4740 or event.EventID == 4767:
                        user = data[4]
                        account_name = data[0]
                        message += account_name

                    event_list.append(event.EventID)
                    single_row = [event_time, event.EventID, message, user, 'Windows Security Event Log', computer]

                    all_events.append(single_row)
                    if event_time > date_from:
                        events_from_date.append(single_row)
                        event_list_from_date.append(event.EventID)
                event_no += 1
                if event_no >= total:
                    print ("Logon/logoff data gathered from Windows Security event log.")
                    win32evtlog.CloseEventLog(hand)
                    print("number of processed records: " + str(event_no))
                    return all_events, event_list, events_from_date, event_list_from_date


def send_notification(message):
    notify = Notify()
    notify.send(message)


def calculate_date(days):
    date = datetime.now() - timedelta(days=int(days))
    date = date.strftime("%Y-%m-%d %H:%M:%S")
    return date


if __name__ == '__main__':
    date_from = calculate_date(sys.argv[1])
    all_events, event_list, events_from_date, event_list_from_date = read_events(date_from)
    # write_to_csv(all_events)
    #
    workbook = xlsxwriter.Workbook(excel_file_path)
    write_data_to_excel(workbook, 'all data', all_events)
    add_chart_to_excel(workbook, 'all data chart', event_list)

    write_data_to_excel(workbook, 'specific data', events_from_date)
    add_chart_to_excel(workbook, 'specific data chart', event_list_from_date)
    workbook.close()
    #
    # send_notification("testus")
    


