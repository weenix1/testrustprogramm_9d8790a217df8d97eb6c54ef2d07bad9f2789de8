using System;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace BlockchainerVisualisation.Views
{
    public partial class MessageWindow : Window
    {

        public string Text { get; set; }

        public MessageWindow()
        {
            InitializeComponent();

        }

        public MessageWindow(string text)
        {
            Text = text;
            InitializeComponent();
        }
        public MessageWindow(string title, string text)
        {
            this.Title = title;
            Text = text;
            InitializeComponent();
            this.Title = title;
        }

        private void Button_OnClick(object? sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
