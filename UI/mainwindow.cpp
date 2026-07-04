#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QFile>
#include <QMessageBox>
#include <thread>
#include <QStackedWidget>
#include <QPainter>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{


    QFile fileQss(":/resources.qss");    //icon inside LoginUserName
    if (fileQss.open(QFile::ReadOnly))
    {
        QString style = QLatin1String(fileQss.readAll());
        setStyleSheet(style);
        fileQss.close();


    } else
    {
        QMessageBox::critical(this, "Error", "resources.qss not found!");
        return;
    }

     setFixedSize(1280,720);
    ui->setupUi(this);
    ui->stackedWidget->setCurrentIndex(0);
    connect(this, &MainWindow::loginTrySignal, this, &MainWindow::on_loginTrySignal);

    //icons for main window

    QIcon lockIcon(":/icons/lock.svg");
   ui->lockLabel->setPixmap(lockIcon.pixmap(60,60));
    ui->lockLabel->setAlignment(Qt::AlignCenter);


    QIcon shieldIcon(":/icons/shield.svg");
    ui->shieldLabel->setPixmap(shieldIcon.pixmap(20,20));



    //page 1


    QAction *userLoginNameIcon = new QAction(this);
    userLoginNameIcon->setIcon(QIcon(":/icons/user.svg"));
    ui->userLoginName->addAction(userLoginNameIcon, QLineEdit::LeadingPosition);

    QAction *userLoginPasswordIcon = new QAction(this);
    userLoginPasswordIcon->setIcon(QIcon(":/icons/key.svg"));
    ui->userLoginPassword->addAction(userLoginPasswordIcon, QLineEdit::LeadingPosition);


    setWindowTitle("BinBin");
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

void MainWindow::paintEvent(QPaintEvent *event)
{
    QMainWindow::paintEvent(event); // сначала рисуем стандартный фон

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing); // сглаживание краёв

    // большой размытый круг слева вверху
    painter.setBrush(QColor(108, 63, 214, 60)); // фиолетовый, полупрозрачный
    painter.setPen(Qt::NoPen); // без рамки
    painter.drawEllipse(-100, -100, 400, 400);

    // круг справа внизу
    painter.setBrush(QColor(108, 63, 214, 40));
    painter.drawEllipse(1050, 450, 350, 350);
}