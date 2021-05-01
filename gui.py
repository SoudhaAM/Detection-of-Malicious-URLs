from tkinter import *
import tkinter.messagebox
#import tkMessageBox
import trainer as tr
#import pandas
import main
#import urlib.request
root = Tk()
width = 800
heigt = 500
root.geometry(f'{width}x{heigt}')

root.title('MALICIOUS URL IDENTIFIER')
frame = Frame(root,bg="light grey")
frame.pack()
bottomframe = Frame(root)
bottomframe.pack( side = TOP )

L1 = Label(frame, text="URLFormat: http:/www.example.com/ ")
L1.pack( side = TOP)
L1 = Label(frame, text="Enter the URL: ")
L1.pack( side = LEFT)
E1 = Entry(frame,bd =5,width=50)
E1.pack(side = RIGHT)
photo =PhotoImage(file=r"OIP.png")
photo.heigt=500
photo.width=500
Button(root,text = ' ',image = photo,height=300,width=500).pack(side =BOTTOM)
def submitCallback():
    url=E1.get()
    main.process_test_url(url,'test_features.csv')
    return_ans =tr.gui_caller('url_features.csv','test_features.csv')
    a=str(return_ans).split()
    if int(a[1])==0:
           tkinter.messagebox.showinfo("URL Checker Result","The URL"+url+"is Benign")
           import webbrowser
           webbrowser.open(url, new=2)
    elif int(a[1])==1:
                tkinter.messagebox.showinfo("URL Checker Result","The URL"+url+"is Malicious")
    else:
                tkinter.messagebox.showinfo("URL Checker Result","The URL"+url+"is Malware")
      
B1 = Button(bottomframe,text = "submit",command=submitCallback,fg="dark blue")
B1.pack()
root.mainloop()

         
