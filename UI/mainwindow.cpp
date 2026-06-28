#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QMessageBox>
#include <thread>
#include <QStackedWidget>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->stackedWidget->setCurrentIndex(0);
    connect(this, &MainWindow::loginTrySignal, this, &MainWindow::on_loginTrySignal);
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