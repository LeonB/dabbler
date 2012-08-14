#!/usr/bin/env python
# -*- coding: utf-8 -*-

import curses
import threading
from cptr import Capture

class table_row(object):
    def __construct(self):
        self.status_code = None
        self.protocol    = None
        self.host        = None
        self.url         = None
        self.method      = None

class table(object):
    headers        = ['Status Code', 'Protocol', 'Host', 'URL', 'Method']
    headers_widths = [0.2, 0.2, 0.25, 0.25, 0.1]
    fields         = ['status_code', 'protocol', 'host', 'url', 'method']

    def absolute_header_widths(self, max_width):
        widths = []

        if sum(self.headers_widths)  != 1:
            raise ValueError

        for i, header in enumerate(self.headers):
            widths.append(int(round(max_width * self.headers_widths[i], 1)))

        return widths

    def draw_header(self, window):
        max_height, max_width = window.getmaxyx()
        widths = self.absolute_header_widths(max_width)

        x = 0
        for i, header in enumerate(self.headers):
            window.addstr(0, x, header, curses.color_pair(0)+curses.A_BOLD)
            x = x + widths[i]

    def draw_rows(self, rows, window):
        max_height, max_width = window.getmaxyx()
        widths = self.absolute_header_widths(max_width)

        y = -1
        for row in rows:
            y  = y + 1

            x = 0
            for i, header in enumerate(self.headers):
                # window.addstr(0, x, header, curses.color_pair(0)+curses.A_BOLD)
                attr = self.fields[i]
                value = getattr(row, attr)
                window.addstr(y, x, str(value), curses.color_pair(0))
                x = x + widths[i]


data = []

def new_request(request, response):
    global t, rows_window
    row = table_row()
    row.status_code = response.status
    row.protocol    = 'HTTP'
    row.host        = request.headers['Host'] if hasattr(request, 'headers') else ''
    row.url         = request.path if hasattr(request, 'path') else ''
    row.method      = 'GET'
    data.append(row)
    t.draw_rows(data, rows_window)
    rows_window.refresh()

t = None
rows_window = None

def main(scr):
    global t, rows_window

    curses.curs_set(0)
    max_height, max_width = scr.getmaxyx()
    scr.refresh()

    ct = threading.Thread(target=Capture, args=(new_request,))
    ct.start()

    header_window = curses.newwin(1, max_width, 0, 0)
    scr.hline(1, 0, '-', max_width)
    rows_window = curses.newwin(max_height-2, max_width, 2, 0)

    # scr.addstr(20, 70, "text with default style")

    t = table()
    t.draw_header(header_window)
    t.draw_rows(data, rows_window)
    header_window.refresh()
    rows_window.refresh()

    while True:
        c = scr.getch()

curses.wrapper(main)
