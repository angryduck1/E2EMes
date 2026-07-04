#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

        private slots:

        //main window
       void on_loginButton_clicked();

        void on_createAccount_clicked();

        void on_recoveryButton_clicked();

        void on_loginTrySignal(bool);  //if login success we send signal to on_loginTrySignal

    //user login Page

       void on_backToMainButton_clicked();

        void on_userLoginButton_clicked();


    signals:
    void loginTrySignal(bool success);

private:
    std::string name;
    std::string password;

    Ui::MainWindow *ui;



};

#endif // MAINWINDOW_H
