import tkinter as tk
from Client import Client

PATH_IMAGE_1 = "book_shop_images/image_product_1.png"
PRICE_PRODUCT_1 = 10


class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.initiate_window()

        self.quantity_product_1 = 0
        self.label_quantity_product_1 = None
        self.amount = 0
        self.label_sum_to_pay = None

        self.widgets_list = []
        self.client = None

    def initiate_window(self):
        self.root.title("BookShop")
        self.root.geometry("360x300")

        # Get the width and height of the screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate the x and y coordinates for the window
        x = int((screen_width - self.root.winfo_reqwidth()) / 3)
        y = int((screen_height - self.root.winfo_reqheight()) / 4)

        # Set the window's position
        self.root.geometry("+{}+{}".format(x, y))

    def erase_screen(self):
        # Erase all the other widgets
        for widget in self.root.winfo_children():
            widget.destroy()

    def shop_window(self):
        if self.root is not None:
            self.erase_screen()

        img_width = 150
        img_height = 150
        self.amount = 0
        self.quantity_product_1 = 0

        image = tk.PhotoImage(file=PATH_IMAGE_1)
        resized_image = image.subsample(image.width() // img_width, image.height() // img_height)
        image_label = tk.Label(self.root, image=resized_image)
        image_label.grid(row=1, column=0, padx=5, pady=10)

        plus_button = tk.Button(self.root, text="+", command=self.increase_quantity)
        plus_button.grid(row=1, column=3, padx=5)
        self.label_quantity_product_1 = tk.Label(self.root, text="Quantity: 0")
        self.label_quantity_product_1.grid(row=1, column=4, padx=5)
        minus_button = tk.Button(self.root, text="-", command=self.decrease_quantity)
        minus_button.grid(row=1, column=5, padx=5)

        price_product_1 = tk.Label(self.root, text=f'Price: {PRICE_PRODUCT_1}$')
        price_product_1.grid(row=2, column=0, padx=10)

        self.label_sum_to_pay = tk.Label(self.root, text=f'Total: {self.amount}$')
        self.label_sum_to_pay.grid(row=4, column=0, padx=10, pady=10)

        pay_button = tk.Button(self.root, text="Pay", command=self.get_card_information)
        pay_button.grid(row=4, column=4, padx=5)

        self.widgets_list = [image_label, plus_button, self.label_quantity_product_1, minus_button, price_product_1,
                             self.label_sum_to_pay, pay_button]

        invisible_widget = tk.Label(self.root, text="")
        invisible_widget.grid(row=6, column=0, padx=10, pady=10)
        self.root.mainloop()

    def get_card_information(self):
        for widget in self.widgets_list:
            widget.destroy()

        label_card_number = tk.Label(self.root, text=f'Card number:')
        label_card_number.grid(row=0, column=0, padx=10, pady=10)
        entry_field = tk.Entry(self.root)
        entry_field.grid(row=0, column=1, padx=10, pady=10)

        label_exp_date = tk.Label(self.root, text=f'Exp date:')
        label_exp_date.grid(row=1, column=0, padx=10, pady=10)
        entry_exp_date = tk.Entry(self.root)
        entry_exp_date.grid(row=1, column=1, padx=10, pady=10)

        ccode_button = tk.Button(self.root, text="Get CCode", command=lambda: self.send_ccode(
            entry_field.get(),
            entry_exp_date.get(),
        ))
        ccode_button.grid(row=2, column=1, pady=10)

    def send_ccode(self, card_number, card_exp_date):
        self.client = Client(card_number, card_exp_date, self.amount)
        response = self.client.send_otp()
        print(response)

        if response == "Invalid Card Info!":
            return

        label_ccode = tk.Label(self.root, text=f'CCode:')
        label_ccode.grid(row=3, column=0, padx=10, pady=10)
        entry_ccode = tk.Entry(self.root)
        entry_ccode.grid(row=3, column=1, padx=10, pady=10)

        pay_button = tk.Button(self.root, text="Make payment", command=lambda: self.start_client(
            card_number,
            card_exp_date,
            entry_ccode.get()
        ))
        pay_button.grid(row=4, column=1, pady=10)

    def start_client(self, card_number, card_exp_date, ccode):
        self.client.ccode = ccode
        response = self.client.run()

        self.erase_screen()

        label_response = tk.Label(self.root, text=response)
        label_response.grid(row=0, column=0, padx=10, pady=10)

        if response == "Transaction successfully accomplished."\
                or "Abort: Transaction failed, no money, poor guy.":
            pay_button = tk.Button(self.root, text="Back", command=self.shop_window)
        else:
            invisible_widget = tk.Label(self.root, text="")
            invisible_widget.grid(row=6, column=0, padx=10, pady=10)

            pay_button = tk.Button(self.root, text="Back", command=self.get_card_information)
            self.widgets_list.append(pay_button)
            self.widgets_list.append(label_response)
        pay_button.grid(row=2, column=0, padx=5)

    def increase_quantity(self):
        self.quantity_product_1 += 1
        self.amount += PRICE_PRODUCT_1
        self.label_quantity_product_1.config(text=f"Quantity: {self.quantity_product_1}")
        self.label_sum_to_pay.config(text=f'Total: {self.amount}$')

    def decrease_quantity(self):
        if self.quantity_product_1 > 0:
            self.quantity_product_1 -= 1
            self.amount -= PRICE_PRODUCT_1
            self.label_quantity_product_1.config(text=f"Quantity: {self.quantity_product_1}")
            self.label_sum_to_pay.config(text=f'Total: {self.amount}$')


interface = GUI()
interface.shop_window()
