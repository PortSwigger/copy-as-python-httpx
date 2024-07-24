import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.utilities.Utilities;
import static burp.api.montoya.http.message.ContentType.*;
import mjson.Json;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.List;



public class HttpxContentMenuItemsProvider implements ContextMenuItemsProvider, ClipboardOwner {

    private final MontoyaApi api;
    private final Utilities utilities;
    public HttpxContentMenuItemsProvider(MontoyaApi api)
    {
        this.api = api;
        utilities = api.utilities();
    }

    //rest of the code is copied from "copy as python-request" project and did some minor edits to work with Montoya API.
    private final static String[] PYTHON_ESCAPE = new String[256];
    static {
        for (int i = 0x00; i <= 0xFF; i++) PYTHON_ESCAPE[i] = String.format("\\x%02x", i);
        for (int i = 0x20; i < 0x80; i++) PYTHON_ESCAPE[i] = String.valueOf((char) i);
        PYTHON_ESCAPE['\n'] = "\\n";
        PYTHON_ESCAPE['\r'] = "\\r";
        PYTHON_ESCAPE['\t'] = "\\t";
        PYTHON_ESCAPE['"'] = "\\\"";
        PYTHON_ESCAPE['\\'] = "\\\\";
    }

    private enum BodyType {JSON, DATA};
    private final Collection<String> IGNORE_HEADERS = new ArrayList<>(Arrays.asList("host:", "content-length:"));
    private static final String PYTHON_TRUE = "True", PYTHON_FALSE = "False", PYTHON_NULL = "None";

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.LOGGER))
        {
            List<Component> menuItemList = new ArrayList<>();

            JMenuItem http1RequestItem = new JMenuItem("Copy as HTTP/1.1");
            JMenuItem http2RequestItem= new JMenuItem("Copy as HTTP/2");

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);

            http1RequestItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    copyMessages(requestResponse.request(), false);
                }
            });
            menuItemList.add(http1RequestItem);

            http2RequestItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    copyMessages(requestResponse.request(), true);
                }
            });
            menuItemList.add(http2RequestItem);

            return menuItemList;
        }

        return null;
    }

    private void copyMessages(HttpRequest httpRequest, boolean isHTTP2Request) {
        StringBuilder pythonCode = new StringBuilder("import httpx");
        String clientVersion = isHTTP2Request ? "client = httpx.Client(http2=True)" : "client = httpx.Client()";
        if (isHTTP2Request) IGNORE_HEADERS.add("connection");
        pythonCode.append("\n\n").append(clientVersion);
        byte[] req = httpRequest.toByteArray().getBytes();
        String prefix = "request" + "_";
        pythonCode.append("\n").append(prefix).append("url = \"");
        pythonCode.append(escapeQuotes(httpRequest.url()));
        pythonCode.append('"');
        List<HttpHeader> headers = httpRequest.headers();
        //temporary fix for some type issues, needs to be refactored with rest of the code
        List<String> strHeaders = new ArrayList<>();
        for (HttpHeader header : headers){
            strHeaders.add(header.toString());
        }
        boolean cookiesExist = processCookies(prefix, pythonCode, strHeaders);
        pythonCode.append('\n').append(prefix).append("headers = {");
        processHeaders(pythonCode, strHeaders);
        pythonCode.append('}');
        BodyType bodyType = processBody(prefix, pythonCode, req, httpRequest);
        pythonCode.append("\nresponse = client.");
        pythonCode.append(httpRequest.method().toLowerCase());
        pythonCode.append('(').append(prefix).append("url, headers=");
        pythonCode.append(prefix).append("headers");
        if (cookiesExist) pythonCode.append(", cookies=").append(prefix).append("cookies");
        if (bodyType != null) {
            String kind = bodyType.toString().toLowerCase();
            pythonCode.append(", ").append(kind).append('=').append(prefix).append(kind);
        }
        pythonCode.append(')');

        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(pythonCode.toString()), this);
    }

    private boolean processCookies(String prefix, StringBuilder py, List<String> headers) {
        ListIterator<String> iter = headers.listIterator();
        boolean cookiesExist = false;
        while (iter.hasNext()) {
            String header = iter.next();
            if (!header.toLowerCase().startsWith("cookie")) continue;
            iter.remove();
            for (String cookie : header.substring(8).split("; ?")) {
                if (cookiesExist) {
                    py.append(", \"");
                } else {
                    cookiesExist = true;
                    py.append('\n').append(prefix).append("cookies = {\"");
                }
                String[] parts = cookie.split("=", 2);
                py.append(escapeQuotes(parts[0]));
                py.append("\": \"");
                py.append(escapeQuotes(parts[1]));
                py.append('"');
            }
        }

        if (cookiesExist) py.append('}');
        return cookiesExist;
    }

    private void processHeaders(StringBuilder py, List<String> headers) {
        boolean firstHeader = true;
        boolean requestLine = true;
        header_loop:
        for (String header : headers) {
            String headerString;
            if (requestLine) {
                requestLine = false;
                continue;
            }
            String lowerCaseHeader = header.toLowerCase();
            for (String headerToIgnore : IGNORE_HEADERS) {
                if (lowerCaseHeader.startsWith(headerToIgnore)) continue header_loop;
            }
            headerString = escapeQuotes(header);
            int colonPos = headerString.indexOf(':');
            if (colonPos == -1) continue;
            if (firstHeader) {
                firstHeader = false;
                py.append('"');
            } else {
                py.append(", \"");
            }
            py.append(headerString, 0, colonPos);
            py.append("\": \"");
            py.append(headerString, colonPos + 2, headerString.length());
            py.append('"');
        }
    }

    private BodyType processBody(String prefix, StringBuilder pythonCode,
                                 byte[] req, HttpRequest ri) {
        int bo = ri.bodyOffset();
        if (bo >= req.length - 2) return null;
        pythonCode.append('\n').append(prefix);
        ContentType contentType = ri.contentType();
        if (contentType == JSON ) {
            try {
                Json root = Json.read(byteSliceToString(req, bo, req.length));
                pythonCode.append("json=");
                escapeJson(root, pythonCode);
                return BodyType.JSON;
            } catch (Exception e) {
                // not valid JSON, treat it like any other kind of data
            }
        }
        pythonCode.append("data = ");
        if (contentType == URL_ENCODED) {
            pythonCode.append('{');
            boolean firstKey = true;
            int keyStart = bo, keyEnd = -1;
            for (int pos = bo; pos < req.length; pos++) {
                byte b = req[pos];
                if (keyEnd == -1) {
                    if (b == (byte)'=') {
                        if (pos == req.length - 1) {
                            if (!firstKey) pythonCode.append(", ");
                            escapeUrlEncodedBytes(req, pythonCode, keyStart, pos);
                            pythonCode.append(": ''");
                        } else {
                            keyEnd = pos;
                        }
                    }
                } else if (b == (byte)'&' || pos == req.length - 1) {
                    if (firstKey) firstKey = false; else pythonCode.append(", ");
                    escapeUrlEncodedBytes(req, pythonCode, keyStart, keyEnd);
                    pythonCode.append(": ");
                    escapeUrlEncodedBytes(req, pythonCode, keyEnd + 1,
                            pos == req.length - 1 ? req.length : pos);
                    keyEnd = -1;
                    keyStart = pos + 1;
                }
            }
            pythonCode.append('}');
        } else {
            escapeBytes(req, pythonCode, bo, req.length);
        }
        return BodyType.DATA;
    }

    private static String escapeQuotes(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private void escapeUrlEncodedBytes(byte[] input, StringBuilder output,
                                       int start, int end) {
        if (end > start) {
            byte[] dec = utilities.urlUtils().decode(ByteArray.byteArray(Arrays.copyOfRange(input, start, end))).getBytes();
            escapeBytes(dec, output, 0, dec.length);
        } else {
            output.append("''");
        }
    }


    private static void escapeJson(Json node, StringBuilder output) {
        if (node.isObject()) {
            output.append('{');
            Map<String, Json> tm = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            tm.putAll(node.asJsonMap());
            final Iterator<Map.Entry<String, Json>> iter = tm.entrySet().iterator();
            if (iter.hasNext()) {
                appendIteratedEntry(iter, output);
                while (iter.hasNext()) {
                    output.append(", ");
                    appendIteratedEntry(iter, output);
                }
            }
            output.append('}');
        } else if (node.isArray()) {
            output.append('[');
            final Iterator<Json> iter = node.asJsonList().iterator();
            if (iter.hasNext()) {
                escapeJson(iter.next(), output);
                while (iter.hasNext()) {
                    output.append(", ");
                    escapeJson(iter.next(), output);
                }
            }
            output.append(']');
        } else if (node.isString()) {
            escapeString(node.asString(), output);
        } else if (node.isBoolean()) {
            output.append(node.asBoolean() ? PYTHON_TRUE : PYTHON_FALSE);
        } else if (node.isNull()) {
            output.append(PYTHON_NULL);
        } else if (node.isNumber()) {
            output.append(node.asString());
        }
    }

    private static void appendIteratedEntry(Iterator<Map.Entry<String, Json>> iter, StringBuilder output) {
        final Map.Entry<String, Json> e = iter.next();
        escapeString(e.getKey(), output);
        output.append(": ");
        escapeJson(e.getValue(), output);
    }

    private static String byteSliceToString(byte[] input, int from, int till) {
        try {
            return new String(input, from, till - from, "ISO-8859-1");
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("All JVMs must support ISO-8859-1");
        }
    }

    private static void escapeString(String input, StringBuilder output) {
        output.append('"');
        int length = input.length();
        for (int pos = 0; pos < length; pos++) {
            output.append(PYTHON_ESCAPE[input.charAt(pos) & 0xFF]);
        }
        output.append('"');
    }

    private static void escapeBytes(byte[] input, StringBuilder output,
                                    int start, int end) {
        output.append('"');
        for (int pos = start; pos < end; pos++) {
            output.append(PYTHON_ESCAPE[input[pos] & 0xFF]);
        }
        output.append('"');
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable transferable) {

    }


}
