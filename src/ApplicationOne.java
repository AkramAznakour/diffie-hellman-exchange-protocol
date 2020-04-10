import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

public class ApplicationOne {

    private static String SERVER_NAME = "localhost";
    private static int PORT = 8088;
    private static int KEY_SIZE = 1024;

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        ApplicationOneFrame applicationOneFrame = new ApplicationOneFrame();

        try {

            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Waiting for application Two on PORT " + serverSocket.getLocalPort() + "...");
            Socket appOneSocket = serverSocket.accept();
            System.out.println("Just connected to " + appOneSocket.getRemoteSocketAddress());
            ObjectOutputStream out = new ObjectOutputStream(appOneSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(appOneSocket.getInputStream());

            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(KEY_SIZE);

            DHParameterSpec dhSpec = paramGen
                    .generateParameters()
                    .getParameterSpec(DHParameterSpec.class);

            BigInteger p = dhSpec.getP();
            BigInteger g = dhSpec.getG();

            applicationOneFrame.setPFieldText(p.toString());
            applicationOneFrame.setGFieldText(g.toString());

            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
            keyGen.initialize(dhParams, new SecureRandom());
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
            KeyPair appOneKeyPair = keyGen.generateKeyPair();

            final BigInteger appOneYPublic = new BigInteger(appOneKeyPair.getPublic().getEncoded());
            final BigInteger appOneGPowerYPrivate = new BigInteger(appOneKeyPair.getPrivate().getEncoded());

            applicationOneFrame.setYFieldText(appOneYPublic.toString());
            applicationOneFrame.setGPowerYFieldText(appOneGPowerYPrivate.toString());

            keyAgreement.init(appOneKeyPair.getPrivate());

            out.writeObject(p);
            out.writeObject(g);
            out.writeObject(appOneKeyPair.getPublic());
            applicationOneFrame.setSendingPGFieldText("OK");
            applicationOneFrame.setSendingGPowerYFieldText("OK");
            final PublicKey appTwoGPowerXPublicKey = (PublicKey) in.readObject();
            final BigInteger appTwoGPowerXPublic = new BigInteger(appTwoGPowerXPublicKey.getEncoded());

            applicationOneFrame.setGPowerXFieldText(appTwoGPowerXPublic.toString());

            keyAgreement.doPhase(appTwoGPowerXPublicKey, true);

            BigInteger key = new BigInteger(keyAgreement.generateSecret());
            applicationOneFrame.setGPowerXYFieldText(key.toString());

            appOneSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static class ApplicationOneFrame extends JFrame {
        private static final String TITLE = "Application One";

        JTextField pField = new JTextField(80),
                gField = new JTextField(80),
                sendingPGField = new JTextField(80),
                yField = new JTextField(80),
                gPowerYField = new JTextField(80),
                sendingGPowerYField = new JTextField(80),
                gPowerXField = new JTextField(80),
                gPowerXYField = new JTextField(80);


        public ApplicationOneFrame() {
            setTitle(TITLE);

            this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());
            addItem(panel, new JLabel("Un grand nombre premier P :"), 0, 0, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Un générateur g:"), 0, 1, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Envoi de p et g:"), 0, 2, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Choix de y:"), 0, 3, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Calcul de g^y:"), 0, 4, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Envoie de g^y:"), 0, 5, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("Réception de g^x:"), 0, 6, 1, 1, GridBagConstraints.EAST);
            addItem(panel, new JLabel("La clé (g^x)^y:"), 0, 7, 1, 1, GridBagConstraints.EAST);

            addItem(panel, pField, 1, 0, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gField, 1, 1, 1, 1, GridBagConstraints.WEST);
            addItem(panel, sendingPGField, 1, 2, 2, 1, GridBagConstraints.WEST);
            addItem(panel, yField, 1, 3, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gPowerYField, 1, 4, 2, 1, GridBagConstraints.WEST);
            addItem(panel, sendingGPowerYField, 1, 5, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gPowerXField, 1, 6, 2, 1, GridBagConstraints.WEST);
            addItem(panel, gPowerXYField, 1, 7, 2, 1, GridBagConstraints.WEST);


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

        public void setSendingPGFieldText(String sendingPGFieldText) {
            this.sendingPGField.setText(sendingPGFieldText);
        }

        public void setYFieldText(String yFieldText) {
            this.yField.setText(yFieldText);
        }

        public void setGPowerYFieldText(String gPowerYFieldText) {
            this.gPowerYField.setText(gPowerYFieldText);
        }

        public void setSendingGPowerYFieldText(String sendingGPowerYFieldText) {
            this.sendingGPowerYField.setText(sendingGPowerYFieldText);
        }

        public void setGPowerXFieldText(String gPowerXFieldText) {
            this.gPowerXField.setText(gPowerXFieldText);
        }

        public void setGPowerXYFieldText(String gPowerXYFieldText) {
            this.gPowerXYField.setText(gPowerXYFieldText);
        }
    }
}



