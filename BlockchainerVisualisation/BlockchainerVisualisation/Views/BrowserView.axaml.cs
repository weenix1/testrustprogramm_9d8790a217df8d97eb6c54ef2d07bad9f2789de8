using System;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Threading;
using Xilium.CefGlue;
using Xilium.CefGlue.Avalonia;
using Xilium.CefGlue.Common.Handlers;

namespace BlockchainerVisualisation.Views
{

    public class BlockRequestHandler : CefResourceRequestHandler
    {
        protected override CefResourceHandler GetResourceHandler(CefBrowser browser, CefFrame frame, CefRequest request)
        {
            var client = new HttpClient();
            var body = "{ \"url\" : \"" + request.Url + "\" } ";

            try
            {
                var r = client.PostAsync("http://127.0.0.1:44402/client/getFileLink",
                    new StringContent(body, Encoding.UTF8, "application/json")).Result;
                var result = new DefaultResourceHandler();
                result.MimeType = r.Content.Headers.ContentType?.MediaType;
                result.Status = (int)r.StatusCode;
                result.StatusText = r.ReasonPhrase;
                var memoryStream = new MemoryStream();
                r.Content.ReadAsStream().CopyTo(memoryStream);
                //result.Response = r.Content.ReadAsStream();
                result.Response = memoryStream;
                return result;
            }
            catch
            {
                // ignored
            }

            return new DefaultResourceHandler { ErrorCode = CefErrorCode.CONNECTION_TIMED_OUT };



        }

        protected override CefCookieAccessFilter? GetCookieAccessFilter(CefBrowser browser, CefFrame frame, CefRequest request)
        {
            return null;
        }
    }


    public class CustomRequestHandler : RequestHandler
    {

        protected override CefResourceRequestHandler GetResourceRequestHandler(CefBrowser browser, CefFrame frame, CefRequest request,
            bool isNavigation, bool isDownload, string requestInitiator, ref bool disableDefaultHandling)
        {
            Debug.Print("request: " + request.Url);

            //if (!request.Url.StartsWith("devtools:"))
            //{
            //    return new BlockRequestHandler();
            //}
            if (request.Url.StartsWith("block://"))
            {
                return new BlockRequestHandler();
            }
            return base.GetResourceRequestHandler(browser, frame, request, isNavigation, isDownload, requestInitiator, ref disableDefaultHandling);
        }
    }

    public partial class BrowserView : UserControl
    {
        private AvaloniaCefBrowser browser;

        public BrowserView()
        {
            InitializeComponent();

            var browserWrapper = this.FindControl<Decorator>("browserWrapper");

            browser = new AvaloniaCefBrowser();
            browser.Address = "block://0000000000000000000000000000000000000000000000000000000000000000/website/index.html";
            browser.LoadStart += OnBrowserLoadStart;
            browser.TitleChanged += OnBrowserTitleChanged;

            browser.RequestHandler = new CustomRequestHandler();
            browserWrapper.Child = browser;
        }
        static Task<object> AsyncCallNativeMethod(Func<object> nativeMethod)
        {
            return Task.Run(() =>
            {
                var result = nativeMethod.Invoke();
                if (result is Task task)
                {
                    if (task.GetType().IsGenericType)
                    {
                        return ((dynamic)task).Result;
                    }

                    return task;
                }

                return result;
            });
        }

        public event Action<string>? TitleChanged;

        private void OnBrowserTitleChanged(object sender, string title)
        {
            TitleChanged?.Invoke(title);
        }

        private void OnBrowserLoadStart(object sender, Xilium.CefGlue.Common.Events.LoadStartEventArgs e)
        {
            if (e.Frame.Browser.IsPopup || !e.Frame.IsMain)
            {
                return;
            }

            Dispatcher.UIThread.Post(() =>
            {
                var addressTextBox = this.FindControl<TextBox>("addressTextBox");

                addressTextBox.Text = e.Frame.Url;
            });
        }

        private void OnAddressTextBoxKeyDown(object sender, global::Avalonia.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                browser.Address = ((TextBox)sender).Text;
            }
        }

        public async void EvaluateJavascript()
        {
            var result = new StringWriter();

            result.WriteLine(await browser.EvaluateJavaScript<string>("\"Hello World!\""));

            result.WriteLine(await browser.EvaluateJavaScript<int>("1+1"));

            result.WriteLine(await browser.EvaluateJavaScript<bool>("false"));

            result.WriteLine(await browser.EvaluateJavaScript<double>("1.5+1.5"));

            result.WriteLine(await browser.EvaluateJavaScript<double>("3+1.5"));

            result.WriteLine(await browser.EvaluateJavaScript<DateTime>("new Date()"));

            result.WriteLine(string.Join(", ", await browser.EvaluateJavaScript<object[]>("[1, 2, 3]")));

            result.WriteLine(string.Join(", ", (await browser.EvaluateJavaScript<ExpandoObject>("(function() { return { a: 'valueA', b: 1, c: true } })()")).Select(p => p.Key + ":" + p.Value)));

            browser.ExecuteJavaScript($"alert(\"{result.ToString().Replace("\r\n", " | ").Replace("\"", "\\\"")}\")");
        }

        public void OpenDevTools()
        {
            browser.ShowDeveloperTools();
        }

        public void Dispose()
        {
            browser.Dispose();
        }
    }
}
