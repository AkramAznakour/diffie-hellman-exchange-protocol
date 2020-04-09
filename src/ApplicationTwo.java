import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;

public class ApplicationTwo {

    private static String SERVER_NAME = "localhost";
    private static int PORT = 8088;
    private static int KEY_SIZE = 512;

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        ApplicationTwoFrame applicationTwoFrame = new ApplicationTwoFrame();

        try {

            System.out.println("Connecting to " + SERVER_NAME + " on port " + PORT);
            Socket appTwoSocket = new Socket(SERVER_NAME, PORT);
            System.out.println("Just connected to " + appTwoSocket.getRemoteSocketAddress());

            ObjectInputStream in = new ObjectInputStream(appTwoSocket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(appTwoSocket.getOutputStream());


            final BigInteger p = (BigInteger) in.readObject();
            final BigInteger g = (BigInteger) in.readObject();
            final PublicKey appOneGPowerYPublicKey = (PublicKey) in.readObject();
            final BigInteger appOneGPowerYPublic = new BigInteger(appOneGPowerYPublicKey.getEncoded());

            applicationTwoFrame.setPFieldText(p.toString());
            applicationTwoFrame.setGFieldText(g.toString());
            applicationTwoFrame.setGPowerXFieldText(appOneGPowerYPublic.toString());

            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
            keyGen.initialize(dhParams, new SecureRandom());
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
            KeyPair appTwoKeyPair = keyGen.generateKeyPair();

            final BigInteger appTwoXPublic = new BigInteger(appTwoKeyPair.getPublic().getEncoded());
            final BigInteger appTwoGPowerXPrivate = new BigInteger(appTwoKeyPair.getPrivate().getEncoded());

            applicationTwoFrame.setXFieldText(appTwoXPublic.toString());
            applicationTwoFrame.setGPowerYFieldText(appTwoGPowerXPrivate.toString());

            out.writeObject(appTwoKeyPair.getPublic());
            keyAgreement.init(appTwoKeyPair.getPrivate());

            applicationTwoFrame.setSendingGPowerXFieldText("OK");
            keyAgreement.doPhase(appOneGPowerYPublicKey, true);

            BigInteger key = new BigInteger(keyAgreement.generateSecret());
            applicationTwoFrame.setGPowerXYFieldText(key.toString());


            appTwoSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static class ApplicationTwoFrame extends JFrame {

        private static final String TITLE = "Application Two";

        JTextField pField = new JTextField(80),
                gField = new JTextField(80),
                xField = new JTextField(80),
                gPowerXField = new JTextField(80),
                sendingGPowerXField = new JTextField(80),
                gPowerYField = new JTextField(80),
                gPowerXYField = new JTextField(80);


        public ApplicationTwoFrame() {
            setTitle(TITLE);
            this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());
            addItem(panel, new JLabel("Réception de p :"), 0, 0, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Réception de g :"), 0, 1, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Choix de x :"), 0, 2, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Calcul de g^x :"), 0, 3, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Envoie de g^x :"), 0, 4, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Réception de g^y :"), 0, 5, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("La clé (g^x)^y :"), 0, 6, 1, 1, GridBagConstraints.EAST);

            addItem(panel, pField, 1, 0, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gField, 1, 1, 1, 1, GridBagConstraints.WEST);
            addItem(panel, xField, 1, 3, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gPowerXField, 1, 2, 2, 1, GridBagConstraints.WEST);
            addItem(panel, sendingGPowerXField, 1, 4, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gPowerYField, 1, 5, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gPowerXYField, 1, 6, 2, 1, GridBagConstraints.WEST);

            this.add(panel);
            this.pack();
            this.setVisible(true);
        }

        private void addItem(JPanel p, JComponent c, int x, int y, int width, int height, int align) {
            GridBagConstraints gc = new GridBagConstraints();
            gc.gridx = x;
            gc.gridy = y;
            gc.gridwidth = width;
            gc.gridheight = height;
            gc.weightx = 100.0;
            gc.weighty = 100.0;
            gc.insets = new Insets(10, 20, 10, 10);
            gc.anchor = align;
            gc.fill = GridBagConstraints.NONE;
            p.add(c, gc);
        }

        public void setPFieldText(String pFieldText) {
            this.pField.setText(pFieldText);
        }

        public void setGFieldText(String gFieldText) {
            this.gField.setText(gFieldText);
        }

        public void setXFieldText(String xFieldText) {
            this.xField.setText(xFieldText);
        }

        public void setGPowerXFieldText(String gPowerXFieldText) {
            this.gPowerXField.setText(gPowerXFieldText);
        }

        public void setSendingGPowerXFieldText(String sendingGPowerXFieldText) {
            this.sendingGPowerXField.setText(sendingGPowerXFieldText);
        }

        public void setGPowerYFieldText(String gPowerYFieldText) {
            this.gPowerYField.setText(gPowerYFieldText);
        }

        public void setGPowerXYFieldText(String gPowerXYFieldText) {
            this.gPowerXYField.setText(gPowerXYFieldText);
        }
    }
}
