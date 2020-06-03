#!/usr/bin/env python3
import sys
import csv
import xlsxwriter
import collections
from notify_run import Notify
import win32evtlog
from datetime import datetime, timedelta

username = "Maciek"
csv_file_path = "C:\\Users\\Maciek\\Desktop\\security_report.csv"
excel_file_path = "C:\\Users\\Maciek\\Desktop\\security_report.xlsx"
workstation = "localhost"
logtype = "Security"
hand = win32evtlog.OpenEventLog(workstation, logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)
event_dictionary = {4624: "Account was successfully logged on: %s",
                    4634: "Account was logged off: %s",
                    4625: "Account failed to log on: %s",
                    4608: "Windows is starting up",
                    4720: "New account was created: %s",
                    4725: "Account was disabled: %s",
                    4726: "Account was deleted: %s",
                    4722: "Account was enabled: %s",
                    4740: "Account was locked out: %s",
                    4767: "Account was unlocked: %s"}
critical_events = {4740, 4720, 4726}


def write_data_to_excel(workbook, sheet_name, all_events):

    worksheet_data = workbook.add_worksheet(sheet_name)
    worksheet_data.set_column('A:A', 20)
    worksheet_data.set_column('B:B', 10)
    worksheet_data.set_column('C:C', 40)
    worksheet_data.set_column('E:E', 30)
    worksheet_data.set_column('F:F', 20)
    header_format = workbook.add_format({'bold': True})
    row = 1
    col = 0

    worksheet_data.write_row('A1', ('timestamp', 'event ID', 'message', 'user', 'source', 'computer',),
                             cell_format=header_format)

    cell_format = workbook.add_format({'align': 'left'})

    for time, event_ID, message, user, source, computer in (all_events):
        worksheet_data.write(row, col, time, cell_format)
        worksheet_data.write(row, col + 1, event_ID, cell_format)
        worksheet_data.write(row, col + 2, message, cell_format)
        worksheet_data.write(row, col + 3, user, cell_format)
        worksheet_data.write(row, col + 4, source, cell_format)
        worksheet_data.write(row, col + 5, computer, cell_format)
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
                    user = ''

                    if (event.EventID == 4624 or event.EventID == 4625) and username in data[5]:
                        user = data[5]
                        message = message % user
                    elif event.EventID == 4634 and username in data[1]:
                        user = data[1]
                        message = message % user
                    elif event.EventID == 4608:
                        user = "N/A"
                    elif (event.EventID == 4720 or event.EventID == 4725 or event.EventID == 4726 \
                            or event.EventID == 4722 or event.EventID == 4740 or event.EventID == 4767) and username\
                            in data[4]:
                        user = data[4]
                        account_name = data[0]
                        message = message % account_name

                    if user in (username, 'N/A'):
                        event_list.append(event.EventID)
                        single_row = [event_time, event.EventID, message, user, 'Windows Security Event Log', computer]
                        all_events.append(single_row)

                        if event_time > date_from:
                            events_from_date.append(single_row)
                            event_list_from_date.append(event.EventID)
                event_no += 1
                if event_no >= total:
                    print("Logon/logoff data gathered from Windows Security event log.")
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

def write_crtitical_events_to_excel(critical_event_list):

    worksheet = workbook.add_worksheet('critical events')
    worksheet.set_column('A:E', 30)
    header_format = workbook.add_format({'bold': True, 'font_color': 'red'})
    worksheet.write_row('A1', ('timestamp', 'critical event ID', 'message'), cell_format=header_format)
    row = 1
    col = 0

    cell_format = workbook.add_format({'bold': True, 'align': 'left'})

    for time, event_ID, message, user, source, computer in critical_event_list:
        worksheet.write(row, col, time, cell_format)
        worksheet.write(row, col + 1, event_ID, cell_format)
        worksheet.write(row, col + 2, message, cell_format)
        row +=1


def handle_critical_events(events_from_date):
    critical_event_list = []
    for critical_event in events_from_date:
        eventID = critical_event[1]
        if eventID in critical_events:
            date = critical_event[0]
            message = critical_event[2] + " on :" + date

            send_notification(message)
            critical_event_list.append(critical_event)

    write_crtitical_events_to_excel(critical_event_list)


if __name__ == '__main__':
    date_from = calculate_date(sys.argv[1])
    all_events, event_list, events_from_date, event_list_from_date = read_events(date_from)

    workbook = xlsxwriter.Workbook(excel_file_path)
    handle_critical_events(events_from_date)
    write_data_to_excel(workbook, 'all data', all_events)
    add_chart_to_excel(workbook, 'all data chart', event_list)
    write_data_to_excel(workbook, 'specific data', events_from_date)
    add_chart_to_excel(workbook, 'specific data chart', event_list_from_date)
    workbook.close()

    write_to_csv(all_events)


