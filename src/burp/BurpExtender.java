package burp;

import javax.swing.*;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.PrintWriter;
import java.text.NumberFormat;
import java.util.List;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;
    private JScrollPane scroll;
    private JLabel countLabel;
    private JFormattedTextField countTextField;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private int count;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("TokenIncrementorJJW");

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                count = 0;

                panel = new JPanel();
                scroll = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scroll.setBorder(BorderFactory.createEmptyBorder());
                countLabel = new JLabel("Count: ");

                NumberFormat format = NumberFormat.getInstance();
                NumberFormatter formatter = new NumberFormatter(format);
                formatter.setValueClass(Integer.class);
                formatter.setMinimum(0);
                formatter.setMaximum(9999);
                formatter.setCommitsOnValidEdit(true);
                formatter.setAllowsInvalid(false);
                countTextField = new JFormattedTextField(formatter);
                countTextField.setValue(0);
                countTextField.setColumns(4);
                countTextField.addPropertyChangeListener("value", new PropertyChangeListener()
                {
                    @Override public void propertyChange(PropertyChangeEvent evt)
                    {
                        count = Integer.parseInt(countTextField.getText());
                    }
                });

                countTextField.setMaximumSize(new Dimension(50, 20));

                GroupLayout layout = new GroupLayout(panel);
                panel.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);

                layout.setHorizontalGroup(layout.createSequentialGroup()
                        .addGap(15)
                        .addGroup(layout.createParallelGroup()
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(countLabel)
                                        .addComponent(countTextField)
                                )
                        )
                );

                layout.setVerticalGroup(layout.createSequentialGroup()
                        .addGap(15)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(countLabel)
                                .addComponent(countTextField)
                        )
                );

                // customize our UI components
                callbacks.customizeUiComponent(scroll);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // set our extension name
                callbacks.setExtensionName("Token Increment JJW");

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        boolean updated = false;

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            IHttpService iHttpService = messageInfo.getHttpService();
            IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());

            List<String> headers = iRequestInfo.getHeaders();
            // get the request body
            String reqBody = request.substring(iRequestInfo.getBodyOffset());

            if (reqBody.contains("IncrementMePlease")) {
                reqBody = reqBody.replaceAll("IncrementMePlease",  String.valueOf(count));
                count++;
                updated = true;
            }

            if (updated) {
                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);

                stdout.println("-----Request After Plugin Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");
            }

            countTextField.setValue(count);
        }
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        return "Token Increment JJW";
    }

    @Override
    public Component getUiComponent() {
        return scroll;
    }
}
