import tkinter as tk

class ToolTip:
    def __init__(self, widget, text=''):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind('<Enter>', self.show_tooltip)
        self.widget.bind('<Leave>', self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20

        # Creates a toplevel window
        self.tooltip = tk.Toplevel(self.widget)
        # Remove the window decorations
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip, text=self.text, 
                      justify='left',
                      background='#2b2b2b',
                      foreground='white',
                      relief='solid',
                      borderwidth=1,
                      padx=5,
                      pady=2)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def update_text(self, new_text):
        self.text = new_text

# Make sure ToolTip is available for import
__all__ = ['ToolTip']