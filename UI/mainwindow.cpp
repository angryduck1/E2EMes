#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QFile>
#include <thread>
#include <QStackedWidget>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

    setFixedSize(1280,720);
    ui->setupUi(this);
    ui->stackedWidget->setCurrentIndex(0);
    connect(this, &MainWindow::loginTrySignal, this, &MainWindow::on_loginTrySignal);

    //icons for main window

    QIcon lockIcon(":/icons/lock.svg");
   ui->lockLabel->setPixmap(lockIcon.pixmap(60,60));
    ui->lockLabel->setAlignment(Qt::AlignCenter);
    ui->lockLabel->setStyleSheet(
    "background-color: #6C3FD6;"
    "border-radius: 40px;"
);

    QIcon shieldIcon(":/icons/shield.svg");
    ui->shieldLabel->setPixmap(shieldIcon.pixmap(20,20));



    //page 1
    QFile fileQss(":/styles/resources.qss");    //icon inside LoginUserName
    if ( fileQss.open(QFile::ReadOnly))
    {
        setStyleSheet(QLatin1String(fileQss.readAll()));

        fileQss.close();
    }
    QAction *userLoginNameIcon = new QAction(this);
    userLoginNameIcon->setIcon(QIcon(":/icons/user.svg"));
    ui->userLoginName->addAction(userLoginNameIcon, QLineEdit::LeadingPosition);

    QAction *userLoginPasswordIcon = new QAction(this);
    userLoginPasswordIcon->setIcon(QIcon(":/icons/key.svg"));
    ui->userLoginPassword->addAction(userLoginPasswordIcon, QLineEdit::LeadingPosition);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_loginButton_clicked()
{

      ui->stackedWidget->setCurrentIndex(1);

}


void MainWindow::on_createAccount_clicked()
{

}

void MainWindow::on_recoveryButton_clicked()
{

}

void MainWindow::on_loginTrySignal(bool success)
{

};
void MainWindow::on_backToMainButton_clicked()
{
ui->stackedWidget->setCurrentIndex(0);
}




void MainWindow::on_userLoginButton_clicked()
{
    QString QUserLogin(ui->userLoginName->text());

     name = QUserLogin.toStdString();

    QString QUserPassword(ui->userLoginPassword->text());

     password = QUserPassword.toStdString();


}