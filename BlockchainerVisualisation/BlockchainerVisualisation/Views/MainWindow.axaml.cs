using System;
using System.Collections;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Newtonsoft.Json;

namespace BlockchainerVisualisation.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            CreateNewTab();

            var mainMenu = this.FindControl<Menu>("mainMenu");
            mainMenu.AttachedToVisualTree += MenuAttached;
        }


        private void MenuAttached(object? sender, VisualTreeAttachmentEventArgs e)
        {
            if (NativeMenu.GetIsNativeMenuExported(this) && sender is Menu mainMenu)
            {
                mainMenu.IsVisible = false;
            }
        }

        private BrowserView ActiveBrowserView => (BrowserView)this.FindControl<TabControl>("tabControl").SelectedContent;

        private void CreateNewTab()
        {
            var tabItems = ((IList)this.FindControl<TabControl>("tabControl").Items);

            var view = new BrowserView();
            var tab = new TabItem();

            var headerPanel = new DockPanel();
            tab.Header = headerPanel;

            var closeButton = new Button()
            {
                Content = "X",
                Padding = new Thickness(2),
                Margin = new Thickness(5, 0, 0, 0)
            };
            closeButton.Click += delegate
            {
                view.Dispose();
                tabItems.Remove(tab);
            };
            DockPanel.SetDock(closeButton, Dock.Right);

            var tabTitle = new TextBlock()
            {
                Text = "New Tab"
            };
            headerPanel.Children.Add(tabTitle);
            headerPanel.Children.Add(closeButton);

            view.TitleChanged += title =>
            {
                Dispatcher.UIThread.Post((Action)(() =>
                {
                    tabTitle.Text = title;
                    ToolTip.SetTip(tab, title);
                }));
            };

            tab.Content = view;

            tabItems.Add(tab);
        }

        private void OnNewTabNativeMenuItemClick(object sender, EventArgs e)
        {
            CreateNewTab();
        }

        private void OnEvaluateJavascriptNativeMenuItemClick(object sender, EventArgs e)
        {
            ActiveBrowserView.EvaluateJavascript();
        }


        private void OnOpenDevToolsNativeMenuItemClick(object sender, EventArgs e)
        {
            ActiveBrowserView.OpenDevTools();
        }

        private void OnNewTabMenuItemClick(object sender, RoutedEventArgs e)
        {
            CreateNewTab();
        }

        private void OnEvaluateJavascriptMenuItemClick(object sender, RoutedEventArgs e)
        {
            ActiveBrowserView.EvaluateJavascript();
        }

        private void OnOpenDevToolsMenuItemClick(object sender, RoutedEventArgs e)
        {
            ActiveBrowserView.OpenDevTools();
        }

         class PublishResponse
         {
             public string? hash;
         }
         class PublishRequest
         {
             public string? folder;
         }


        private async void OnPublishMenuItemClick(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFolderDialog();
            var folder = await ofd.ShowAsync(this);
            if (folder == null) return;

            var client = new HttpClient();

            var body = JsonConvert.SerializeObject(new PublishRequest() { folder = folder });

           

            try
            {
                var r = client.PostAsync("http://127.0.0.1:44402/client/publish",
                    new StringContent(body, Encoding.UTF8, "application/json")).Result;


                if (r.IsSuccessStatusCode)
                {
                    var result = await r.Content.ReadAsStringAsync();
                    var pResponse = JsonConvert.DeserializeObject<PublishResponse>(result);
                    if (pResponse != null)
                    {
                        Debug.Print("Hash:" + pResponse.hash);
                        await new MessageWindow("Publish Successful", "Published Data at:" + pResponse.hash).ShowDialog(this);
                    }
                    else
                    {
                        await new MessageWindow("Error Publish", "Could not publish:" + await r.Content.ReadAsStringAsync()).ShowDialog(this);
                    }
                }
                else
                {
                    await new MessageWindow("Error Publish", "Could not publish:" + await r.Content.ReadAsStringAsync()).ShowDialog(this);
                }

                //return result;
            }
            catch(Exception ex)
            {
                await new MessageWindow("Error Publish", "Could not publish:" + ex).ShowDialog(this);
            }


        }

    }
}