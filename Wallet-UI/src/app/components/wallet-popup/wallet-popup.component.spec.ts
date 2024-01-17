import { ComponentFixture, TestBed } from '@angular/core/testing';

import { WalletPopupComponent } from './wallet-popup.component';

describe('WalletPopupComponent', () => {
  let component: WalletPopupComponent;
  let fixture: ComponentFixture<WalletPopupComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [WalletPopupComponent]
    });
    fixture = TestBed.createComponent(WalletPopupComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
